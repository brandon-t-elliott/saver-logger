#!/usr/bin/env python3
# encoding: utf-8
"""
Logic tests for SAVER_LOGGER.py, runnable without Burp or a JVM.

No network traffic is generated: the Burp API is fully mocked and the URLs in
fixtures are inert strings. The only I/O is CSV files written to a temp dir.

Every test asserts CORRECT behavior. On the unfixed main branch the tests
marked with a "Demonstrates:" line fail, reproducing the bugs claimed in the
corresponding fix PRs; on the fix branches they pass. See tests/README.md for
the branch-by-branch expectations and how to run the suite against a branch.
"""
import csv
import gc
import io
import os
import shutil
import sys
import tempfile
import time
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, REPO_ROOT)

import java_stubs
java_stubs.install()

import SAVER_LOGGER


# --------------- Burp API mocks --------------- #

class MockRequestInfo(object):
    def __init__(self, url, method, param_count):
        self._url = url
        self._method = method
        self._params = [object()] * param_count

    def getUrl(self):
        return self._url

    def getMethod(self):
        return self._method

    def getParameters(self):
        return self._params


class MockResponseInfo(object):
    def __init__(self, status):
        self._status = status

    def getStatusCode(self):
        return self._status


class MockHttpService(object):
    def __init__(self, host):
        self._host = host

    def getHost(self):
        return self._host


class MockMessage(object):
    """One HTTP message. The same object is passed for the request and the
    response event, mirroring Burp's legacy IHttpListener behavior."""

    def __init__(self, url, host='ginandjuice.shop', method='GET',
                 param_count=0, status=200):
        self.request_info = MockRequestInfo(url, method, param_count)
        self._status = status
        self._service = MockHttpService(host)
        self._responded = False

    def getRequest(self):
        return b'REQUEST-BYTES'

    def getResponse(self):
        if self._responded:
            return ('RESPONSE-BYTES', self._status)
        return None

    def getHttpService(self):
        return self._service


class MockHelpers(object):
    def analyzeRequest(self, message):
        return message.request_info

    def analyzeResponse(self, response_bytes):
        return MockResponseInfo(response_bytes[1])


class MockCallbacks(object):
    def __init__(self):
        self._helpers = MockHelpers()

    def getHelpers(self):
        return self._helpers

    def setExtensionName(self, name):
        pass

    def registerHttpListener(self, listener):
        pass

    def registerExtensionStateListener(self, listener):
        pass

    def addSuiteTab(self, tab):
        pass

    def getToolName(self, flag):
        return 'Proxy'

    def getBurpVersion(self):
        return ['Burp Suite Professional', '2025', '.8.1']


class UnserializableField(object):
    """A log cell whose string conversion fails, to force an export error
    after the output stream is already open."""

    def __str__(self):
        raise ValueError('string conversion failed during export')


# CSV row layout written by _write_full_csv
COL_HOST = 1
COL_URL = 3
COL_REQUEST_COUNT = 6
COL_INSERTION_POINTS = 7

SAMPLE_ROW = [1, 'ginandjuice.shop', 'GET', 'https://ginandjuice.shop/catalog',
              '200', 'Proxy', 1, 0, '2026-08-10 12:00:00',
              '2026-08-10 12:00:01']


def read_csv_rows(path):
    """Return (header, data_rows), skipping metadata comment lines."""
    with io.open(path, encoding='utf-8') as handle:
        lines = [line for line in handle.read().splitlines()
                 if line.strip() and not line.startswith('#')]
    rows = list(csv.reader(lines))
    return rows[0], rows[1:]


def read_raw(path):
    with io.open(path, encoding='utf-8') as handle:
        return handle.read()


class SaverLoggerTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='saver_logger_test_')
        self.ext = SAVER_LOGGER.BurpExtender()
        self.ext.registerExtenderCallbacks(MockCallbacks())
        self.ext.backup_folder = self.tmp

    def tearDown(self):
        self.ext.shutdown_flag = True
        if self.ext.worker_thread:
            self.ext.worker_thread.join(2000)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _stop_worker(self):
        """Stop the background worker so queued items stay queued."""
        self.ext.shutdown_flag = True
        self.ext.worker_thread.join(2000)

    def _respond(self, msg, tool=4):
        msg._responded = True
        self.ext._handle_response(tool, msg)

    def _rows_by_url(self):
        return dict((row[COL_URL], row) for row in self.ext.log_data)

    # ---------- sanity ---------- #

    def test_smoke_extension_loads(self):
        """Extension initializes against the mocked Burp API."""
        self.assertEqual(self.ext.request_counter, 0)
        self.assertEqual(self.ext.log_data, [])

    def test_per_url_request_count_increments(self):
        """Repeated requests to one URL get request_count 1, 2, ..."""
        for _ in range(2):
            msg = MockMessage('https://ginandjuice.shop/catalog')
            self.ext._handle_request(4, msg)
            self._respond(msg)
        counts = [row[COL_REQUEST_COUNT] for row in self.ext.log_data]
        self.assertEqual(counts, [1, 2])

    # ---------- request/response correlation (fix-request-correlation) ---------- #

    def test_concurrent_requests_keep_their_own_data(self):
        """Demonstrates: two in-flight requests must not swap tracking data.

        On main, _handle_request guesses its serial as request_counter + 1
        without incrementing, so both requests write to the same tracking key
        and the first row is built from the second request's data.
        """
        msg_a = MockMessage('https://ginandjuice.shop/a', param_count=2)
        msg_b = MockMessage('https://ginandjuice.shop/b', param_count=0)
        self.ext._handle_request(4, msg_a)
        self.ext._handle_request(4, msg_b)
        self._respond(msg_a)
        self._respond(msg_b)

        rows = self._rows_by_url()
        self.assertEqual(rows['https://ginandjuice.shop/a'][COL_INSERTION_POINTS], 2,
                         "row for /a must carry /a's own insertion point count")
        self.assertEqual(rows['https://ginandjuice.shop/b'][COL_INSERTION_POINTS], 0,
                         "row for /b must carry /b's own insertion point count")

    def test_out_of_order_responses_keep_their_own_data(self):
        """Demonstrates: responses arriving out of order must still match
        their own request's tracking entry."""
        msg_a = MockMessage('https://ginandjuice.shop/slow', param_count=3)
        msg_b = MockMessage('https://ginandjuice.shop/fast', param_count=1)
        self.ext._handle_request(4, msg_a)
        self.ext._handle_request(4, msg_b)
        self._respond(msg_b)  # fast response overtakes the slow one
        self._respond(msg_a)

        rows = self._rows_by_url()
        self.assertEqual(rows['https://ginandjuice.shop/slow'][COL_INSERTION_POINTS], 3)
        self.assertEqual(rows['https://ginandjuice.shop/fast'][COL_INSERTION_POINTS], 1)

    def test_in_flight_requests_keep_tracking_entries(self):
        """Demonstrates: every in-flight request must keep its own tracking
        entry until its response arrives - entries may be evicted only when
        the message itself is gone, never while a response is still possible.

        On main, all in-flight requests share one guessed key, so 1500
        in-flight requests leave a single tracking entry.
        """
        messages = [MockMessage('https://ginandjuice.shop/inflight/%d' % i,
                                param_count=1)
                    for i in range(1500)]
        for msg in messages:
            self.ext._handle_request(4, msg)

        self.assertEqual(len(self.ext.request_tracking), 1500,
                         'every in-flight request must keep its own entry')

        for msg in messages:
            self._respond(msg)
        self.assertEqual(len(self.ext.request_tracking), 0,
                         'entries must be removed once the response is logged')
        self.assertEqual(len(self.ext.log_data), 1500)

    def test_tracking_entries_die_with_their_messages(self):
        """Demonstrates (against fix-request-correlation as first pushed):
        tracking entries for messages the tool has abandoned - no response
        will ever arrive - must be released with the message, not held
        strongly until a timed purge.

        Passes on main only via the overwrite bug (single shared key).
        """
        for i in range(1500):
            msg = MockMessage('https://ginandjuice.shop/abandoned/%d' % i)
            self.ext._handle_request(4, msg)
            # msg goes out of scope here: no response will ever arrive
        gc.collect()

        self.assertLessEqual(len(self.ext.request_tracking), 10,
                             'abandoned messages must not leave tracking '
                             'entries behind')

    # ---------- queue / worker path ---------- #

    def test_worker_processes_queued_messages_end_to_end(self):
        """Characterization of the queue/worker path before the performance
        rework: messages queued via processHttpMessage must be processed
        into log rows by the background worker."""
        msg = MockMessage('https://ginandjuice.shop/live', param_count=1)
        self.ext.processHttpMessage(4, True, msg)
        msg._responded = True
        self.ext.processHttpMessage(4, False, msg)

        deadline = time.time() + 5
        while time.time() < deadline and not self.ext.log_data:
            time.sleep(0.05)

        self.assertEqual(len(self.ext.log_data), 1,
                         'worker must drain the queue into log rows')
        self.assertEqual(self.ext.log_data[0][COL_URL],
                         'https://ginandjuice.shop/live')

    # ---------- CSV integrity (csv-integrity) ---------- #

    def test_csv_preserves_commas_in_fields(self):
        """Demonstrates: exporting must not corrupt logged data.

        On main, commas in any field are replaced with semicolons, silently
        rewriting URLs like ?ids=1,2,3 in the audit trail.
        """
        url = 'https://ginandjuice.shop/api?ids=1,2,3'
        row = list(SAMPLE_ROW)
        row[COL_URL] = url
        self.ext.log_data.append(row)
        path = os.path.join(self.tmp, 'out.csv')
        self.assertTrue(self.ext._write_full_csv(path))

        _, rows = read_csv_rows(path)
        self.assertEqual(rows[0][COL_URL], url,
                         'URL must survive the export round-trip unmodified')

    def test_csv_formula_injection_neutralized(self):
        """Demonstrates: attacker-influenced fields must not be exported as
        live spreadsheet formulas (CSV/formula injection), for every
        formula-trigger character spreadsheets honor."""
        triggers = ['=', '+', '-', '@', '\t']
        for index, trigger in enumerate(triggers):
            row = list(SAMPLE_ROW)
            row[0] = index + 1
            row[COL_HOST] = trigger + 'HYPERLINK("https://ginandjuice.shop")'
            self.ext.log_data.append(row)
        path = os.path.join(self.tmp, 'out.csv')
        self.assertTrue(self.ext._write_full_csv(path))

        _, rows = read_csv_rows(path)
        for trigger, row in zip(triggers, rows):
            self.assertFalse(row[COL_HOST].startswith(trigger),
                             'exported cell must not begin with formula '
                             'trigger %r: got %r' % (trigger, row[COL_HOST]))

    def test_export_failure_closes_file_handle(self):
        """Demonstrates: when a write fails mid-export, _write_full_csv
        returns False but leaves the output stream open; the handle must be
        closed on all paths."""
        java_stubs.BufferedWriter.instances = []
        row = list(SAMPLE_ROW)
        row[COL_URL] = UnserializableField()
        self.ext.log_data.append(row)
        path = os.path.join(self.tmp, 'export-failure.csv')

        self.assertFalse(self.ext._write_full_csv(path))

        self.assertEqual(len(java_stubs.BufferedWriter.instances), 1)
        self.assertTrue(java_stubs.BufferedWriter.instances[0].closed,
                        'export failure must still close the output stream')

    def test_csv_footer_records_burp_version(self):
        """Demonstrates: the footer writes getBurpVersion()[0], which is only
        the product name - the version numbers are dropped."""
        self.ext.log_data.append(list(SAMPLE_ROW))
        path = os.path.join(self.tmp, 'out.csv')
        self.assertTrue(self.ext._write_full_csv(path))

        version_lines = [line for line in read_raw(path).splitlines()
                         if line.startswith('# Burp Suite Version:')]
        self.assertTrue(version_lines, 'footer must contain a version line')
        self.assertIn('2025', version_lines[0],
                      'footer must include the actual version numbers')

    # ---------- reliability (reliability-fixes) ---------- #

    def test_unload_saves_queued_messages(self):
        """Demonstrates: messages still sitting in the processing queue at
        unload time must be included in the crash-safe exit backup."""
        self._stop_worker()  # simulate the worker losing the shutdown race

        msg = MockMessage('https://ginandjuice.shop/tail', param_count=1)
        self.ext.processHttpMessage(4, True, msg)
        msg._responded = True
        self.ext.processHttpMessage(4, False, msg)

        self.ext.extensionUnloaded()

        backups = [name for name in os.listdir(self.tmp)
                   if name.startswith('SAVER_LOGGER_AUTOSAVE_')]
        self.assertTrue(backups,
                        'exit backup must include messages still in the queue')
        content = read_raw(os.path.join(self.tmp, backups[0]))
        self.assertIn('https://ginandjuice.shop/tail', content)

    def test_auto_backup_survives_missing_folder(self):
        """Demonstrates: auto-backup to a nonexistent folder currently fails
        silently (console-only error); it must create the folder instead."""
        self.ext.backup_folder = os.path.join(self.tmp, 'does', 'not', 'exist')
        self.ext.log_data.append(list(SAMPLE_ROW))

        self.ext._auto_backup()

        path = os.path.join(self.ext.backup_folder, 'SAVER_LOGGER_AUTOSAVE.csv')
        self.assertTrue(os.path.exists(path),
                        'auto-backup must create the backup folder if missing')


if __name__ == '__main__':
    unittest.main(verbosity=2)
