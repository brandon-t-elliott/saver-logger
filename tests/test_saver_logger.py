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
import io
import os
import shutil
import sys
import tempfile
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


class FakeClock(object):
    """Deterministic replacement for the time module: advances 1s per call."""

    def __init__(self, start=1000000.0):
        self.now = start

    def time(self):
        self.now += 1.0
        return self.now


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

    def test_tracking_dict_stays_bounded(self):
        """Property of the fix: unanswered requests must not accumulate
        forever in the tracking dict.

        Note: this passes on main too, but only because main's overwrite bug
        keeps the dict at size ~1 - the same defect the two tests above fail
        on. It exists to pin the bounded-memory property of the keyed design.
        """
        original = getattr(SAVER_LOGGER, 'time', None)
        SAVER_LOGGER.time = FakeClock()
        try:
            for i in range(1500):
                msg = MockMessage('https://ginandjuice.shop/unanswered/%d' % i)
                self.ext._handle_request(4, msg)
            self.assertLess(len(self.ext.request_tracking), 1500,
                            'unanswered requests must not accumulate forever')
        finally:
            if original is not None:
                SAVER_LOGGER.time = original

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
        live spreadsheet formulas (CSV/formula injection)."""
        row = list(SAMPLE_ROW)
        row[COL_HOST] = '=2+5+cmd|calc'
        self.ext.log_data.append(row)
        path = os.path.join(self.tmp, 'out.csv')
        self.assertTrue(self.ext._write_full_csv(path))

        _, rows = read_csv_rows(path)
        cell = rows[0][COL_HOST]
        self.assertFalse(cell.startswith(('=', '+', '@')),
                         'exported cell must not begin with a formula trigger '
                         'character: %r' % cell)

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
