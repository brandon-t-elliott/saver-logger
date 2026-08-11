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
import re
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
                 param_count=0, status=200, response_payload='RESPONSE-BYTES'):
        self.request_info = MockRequestInfo(url, method, param_count)
        self._status = status
        self._service = MockHttpService(host)
        self._responded = False
        self._response_payload = response_payload

    def getRequest(self):
        return b'REQUEST-BYTES'

    def getResponse(self):
        if self._responded:
            return (self._response_payload, self._status)
        return None

    def getHttpService(self):
        return self._service


class MockHelpers(object):
    def analyzeRequest(self, message):
        return message.request_info

    def analyzeResponse(self, response_bytes):
        # A response payload of 'MALFORMED' models bytes Burp cannot parse,
        # exercising the extension's 'Error' status fallback.
        if response_bytes[0] == 'MALFORMED':
            raise ValueError('malformed response')
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

    # Burp's ITool flag constants -> display names, so a simulated session
    # can span multiple tools the way a real one does.
    TOOL_NAMES = {
        4: 'Proxy', 8: 'Spider', 16: 'Scanner', 32: 'Intruder',
        64: 'Repeater', 128: 'Sequencer', 1024: 'Extender',
    }

    def getToolName(self, flag):
        return self.TOOL_NAMES.get(flag, 'Extender')

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

    def _confirm_yes(self):
        """Make JOptionPane confirm dialogs auto-answer YES (headless)."""
        SAVER_LOGGER.JOptionPane.YES_OPTION = 0
        SAVER_LOGGER.JOptionPane.showConfirmDialog = staticmethod(lambda *a: 0)

    def _restore_confirm(self):
        for name in ('YES_OPTION', 'showConfirmDialog'):
            if hasattr(SAVER_LOGGER.JOptionPane, name):
                delattr(SAVER_LOGGER.JOptionPane, name)

    def _drain_worker(self, expected_rows, timeout=8):
        """Block until the background worker has logged expected_rows."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.ext.data_lock.lock()
            try:
                done = len(self.ext.log_data) >= expected_rows
            finally:
                self.ext.data_lock.unlock()
            if done:
                return
            time.sleep(0.02)
        self.fail('worker did not log %d rows in time (got %d)' %
                  (expected_rows, len(self.ext.log_data)))

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

    # ---------- functional coverage (characterization; pass on every branch) ---------- #

    def test_logged_row_records_message_metadata(self):
        """A single request/response pair produces one complete log row."""
        msg = MockMessage('https://ginandjuice.shop/catalog?item=1',
                          host='ginandjuice.shop', method='POST',
                          param_count=2, status=302)
        self.ext._handle_request(4, msg)
        self._respond(msg)

        self.assertEqual(len(self.ext.log_data), 1)
        row = self.ext.log_data[0]
        self.assertEqual(row[0], 1)                   # Serial No
        self.assertEqual(row[1], 'ginandjuice.shop')  # Host
        self.assertEqual(row[2], 'POST')              # Request Method
        self.assertEqual(row[3], 'https://ginandjuice.shop/catalog?item=1')
        self.assertEqual(row[4], '302')               # Status Code
        self.assertEqual(row[5], 'Proxy')             # Tool Name
        self.assertEqual(row[6], 1)                   # Request Count
        self.assertEqual(row[7], 2)                   # Insertion Point Count
        timestamp = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')
        self.assertTrue(timestamp.match(row[8]), 'Start Time format')
        self.assertTrue(timestamp.match(row[9]), 'End Time format')

    def test_serial_numbers_increment_in_log_order(self):
        for i in range(3):
            msg = MockMessage('https://ginandjuice.shop/page/%d' % i)
            self.ext._handle_request(4, msg)
            self._respond(msg)
        self.assertEqual([row[0] for row in self.ext.log_data], [1, 2, 3])

    def test_missing_response_logged_with_placeholder_status(self):
        """A message whose response never materialized logs status '-'."""
        msg = MockMessage('https://ginandjuice.shop/timeout')
        self.ext._handle_request(4, msg)
        self.ext._handle_response(4, msg)  # getResponse() still returns None
        self.assertEqual(self.ext.log_data[0][4], '-')

    def test_unparseable_response_logged_with_error_status(self):
        """A response analyzeResponse cannot parse logs status 'Error'."""
        def failing_analyze(response_bytes):
            raise ValueError('malformed response')
        self.ext._helpers.analyzeResponse = failing_analyze

        msg = MockMessage('https://ginandjuice.shop/garbled')
        self.ext._handle_request(4, msg)
        self._respond(msg)
        self.assertEqual(self.ext.log_data[0][4], 'Error')

    def test_export_writes_metadata_and_column_header(self):
        self.ext.log_data.append(list(SAMPLE_ROW))
        path = os.path.join(self.tmp, 'out.csv')
        self.assertTrue(self.ext._write_full_csv(path))

        raw = read_raw(path)
        self.assertIn('# Generated By: SAVER_LOGGER', raw)
        self.assertIn('# Session ID: %s' % self.ext.runtime_id, raw)
        self.assertIn('# Total Requests: 1', raw)
        self.assertIn('# Total Requests Logged: 1', raw)

        header, rows = read_csv_rows(path)
        self.assertEqual(header,
                         ['Serial No', 'Host', 'Request Method', 'URL',
                          'Status Code', 'Tool Name', 'Request Count',
                          'Insertion Point Count', 'Start Time', 'End Time'])
        self.assertEqual(len(rows), 1)

    def test_export_with_no_data_returns_false(self):
        path = os.path.join(self.tmp, 'empty.csv')
        self.assertFalse(self.ext._write_full_csv(path))
        self.assertFalse(os.path.exists(path))

    def test_unicode_fields_survive_export(self):
        url = u'https://ginandjuice.shop/café?drink=\U0001f378'
        row = list(SAMPLE_ROW)
        row[COL_URL] = url
        self.ext.log_data.append(row)
        path = os.path.join(self.tmp, 'unicode.csv')
        self.assertTrue(self.ext._write_full_csv(path))

        _, rows = read_csv_rows(path)
        self.assertEqual(rows[0][COL_URL], url)

    def test_backup_now_creates_timestamped_backup(self):
        self.ext.log_data.append(list(SAMPLE_ROW))
        self.ext.backup_now(None)

        backups = [name for name in os.listdir(self.tmp)
                   if name.startswith('SAVER_LOGGER_BACKUP_')]
        self.assertEqual(len(backups), 1)
        self.assertIn('ginandjuice.shop',
                      read_raw(os.path.join(self.tmp, backups[0])))

    def test_auto_backup_uses_single_overwritten_file(self):
        self.ext._auto_backup()  # no data yet: must not create a file
        self.assertEqual(os.listdir(self.tmp), [])

        self.ext.log_data.append(list(SAMPLE_ROW))
        self.ext._auto_backup()
        second = list(SAMPLE_ROW)
        second[0] = 2
        self.ext.log_data.append(second)
        self.ext._auto_backup()

        autosaves = [name for name in os.listdir(self.tmp)
                     if name.startswith('SAVER_LOGGER_AUTOSAVE')]
        self.assertEqual(autosaves, ['SAVER_LOGGER_AUTOSAVE.csv'])
        self.assertIn('# Total Requests: 2',
                      read_raw(os.path.join(self.tmp, autosaves[0])))

    def test_clear_logs_resets_memory_but_keeps_exported_files(self):
        for i in range(2):
            msg = MockMessage('https://ginandjuice.shop/page/%d' % i)
            self.ext._handle_request(4, msg)
            self._respond(msg)

        # Export to disk before clearing; that file must survive the clear.
        export_path = os.path.join(self.tmp, 'before_clear.csv')
        self.assertTrue(self.ext._write_full_csv(export_path))
        exported_before = read_raw(export_path)

        self._confirm_yes()
        try:
            self.ext.clear_logs(None)
        finally:
            self._restore_confirm()

        # In-memory state is reset...
        self.assertEqual(self.ext.log_data, [])
        self.assertEqual(self.ext.request_counter, 0)

        # ...but the previously exported file is untouched on disk.
        self.assertTrue(os.path.exists(export_path),
                        'Clear Logs must not delete exported files')
        self.assertEqual(read_raw(export_path), exported_before,
                         'exported file contents must be unchanged by a clear')

        # Logging starts fresh after a clear
        msg = MockMessage('https://ginandjuice.shop/fresh')
        self.ext._handle_request(4, msg)
        self._respond(msg)
        self.assertEqual(self.ext.log_data[0][0], 1)
        self.assertEqual(self.ext.log_data[0][6], 1)

    def test_worker_survives_processing_errors(self):
        """One malformed message must not kill the worker thread."""
        broken = MockMessage('https://ginandjuice.shop/broken')
        broken.request_info = None  # analyzeRequest yields nothing usable
        self.ext.processHttpMessage(4, True, broken)

        good = MockMessage('https://ginandjuice.shop/after-error',
                           param_count=1)
        self.ext.processHttpMessage(4, True, good)
        good._responded = True
        self.ext.processHttpMessage(4, False, good)

        deadline = time.time() + 5
        while time.time() < deadline and not self.ext.log_data:
            time.sleep(0.05)
        self.assertEqual(len(self.ext.log_data), 1)
        self.assertEqual(self.ext.log_data[0][COL_URL],
                         'https://ginandjuice.shop/after-error')

    def test_backup_scheduler_configuration(self):
        self.ext.backup_interval_seconds = 120
        self.ext._start_backup_scheduler()
        task, delay, period = self.ext.backup_timer.scheduled[0]
        self.assertEqual(delay, 10000)
        self.assertEqual(period, 120000)

        timer = self.ext.backup_timer
        self.ext.auto_backup_enabled = False
        self.ext._start_backup_scheduler()
        self.assertTrue(timer.cancelled,
                        'disabling auto-backup must cancel the timer')

    def test_auto_backup_survives_missing_folder(self):
        """Demonstrates: auto-backup to a nonexistent folder currently fails
        silently (console-only error); it must create the folder instead."""
        self.ext.backup_folder = os.path.join(self.tmp, 'does', 'not', 'exist')
        self.ext.log_data.append(list(SAMPLE_ROW))

        self.ext._auto_backup()

        path = os.path.join(self.ext.backup_folder, 'SAVER_LOGGER_AUTOSAVE.csv')
        self.assertTrue(os.path.exists(path),
                        'auto-backup must create the backup folder if missing')


# Burp ITool flag constants used by the simulated session
TOOL_PROXY = 4
TOOL_SCANNER = 16
TOOL_INTRUDER = 32
TOOL_REPEATER = 64


class EndToEndSessionTest(unittest.TestCase):
    """Drive a realistic multi-tool Burp session through the real public
    entry point (processHttpMessage -> queue -> background worker) and verify
    that every message is logged and exported correctly.

    The session mixes tools, sequential and concurrent in-flight requests,
    out-of-order responses, repeated URLs, a comma-bearing URL, a dropped
    connection (no response body), and an unparseable response. Because it
    asserts correct correlation and CSV integrity, it is red on main and
    green once all fix branches are applied - a single check that the whole
    system works together.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='saver_logger_e2e_')
        self.ext = SAVER_LOGGER.BurpExtender()
        self.ext.registerExtenderCallbacks(MockCallbacks())
        self.ext.backup_folder = self.tmp

    def tearDown(self):
        self.ext.shutdown_flag = True
        if self.ext.worker_thread:
            self.ext.worker_thread.join(2000)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _feed(self, events):
        """Deliver (toolFlag, is_request, message) events in order, exactly
        as Burp's IHttpListener would call the extension."""
        for tool, is_request, msg in events:
            self.ext.processHttpMessage(tool, is_request, msg)

    def _await_rows(self, expected, timeout=8):
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.ext.data_lock.lock()
            try:
                if len(self.ext.log_data) >= expected:
                    return
            finally:
                self.ext.data_lock.unlock()
            time.sleep(0.02)
        self.fail('session logged %d/%d rows before timeout' %
                  (len(self.ext.log_data), expected))

    def test_full_session_is_logged_and_exported_correctly(self):
        # --- build the messages of the session ---
        p1 = MockMessage('https://ginandjuice.shop/home', method='GET',
                         param_count=0, status=200)
        p2 = MockMessage('https://ginandjuice.shop/home', method='GET',
                         param_count=0, status=200)           # repeat of /home
        r1 = MockMessage('https://ginandjuice.shop/login', method='POST',
                         param_count=2, status=302)
        r2 = MockMessage('https://ginandjuice.shop/login', method='POST',
                         param_count=2, status=401)           # repeat of /login
        s1 = MockMessage('https://ginandjuice.shop/search?q=1,2', method='GET',
                         param_count=1, status=200)           # comma in URL
        i1 = MockMessage('https://ginandjuice.shop/item?id=1', method='GET',
                         param_count=1, status=500)
        x1 = MockMessage('https://ginandjuice.shop/timeout', method='GET',
                         param_count=0, status=200)           # dropped: no body
        e1 = MockMessage('https://ginandjuice.shop/error', method='GET',
                         param_count=1, status=200,
                         response_payload='MALFORMED')        # unparseable

        for msg in (p1, p2, r1, r2, s1, i1, x1, e1):
            if msg is not x1:
                msg._responded = True
        e1._responded = True
        x1._responded = False  # dropped connection: response event, empty body

        # --- deliver events; response order is what assigns serial numbers ---
        self._feed([
            (TOOL_PROXY,    True,  p1), (TOOL_PROXY,    False, p1),
            (TOOL_PROXY,    True,  p2), (TOOL_PROXY,    False, p2),
            (TOOL_REPEATER, True,  r1),                        # r1, r2 in flight
            (TOOL_REPEATER, True,  r2),
            (TOOL_REPEATER, False, r1), (TOOL_REPEATER, False, r2),
            (TOOL_SCANNER,  True,  s1),                        # s1, i1 in flight
            (TOOL_INTRUDER, True,  i1),
            (TOOL_INTRUDER, False, i1),                        # i1 responds first
            (TOOL_SCANNER,  False, s1),                        # out of order
            (TOOL_PROXY,    True,  x1), (TOOL_PROXY,    False, x1),
            (TOOL_PROXY,    True,  e1), (TOOL_PROXY,    False, e1),
        ])

        self._await_rows(8)
        # give the worker a beat to ensure nothing extra is appended
        time.sleep(0.1)
        self.assertEqual(len(self.ext.log_data), 8,
                         'exactly one row per response event')

        # --- export the whole session and read it back ---
        export_path = os.path.join(self.tmp, 'session.csv')
        self.assertTrue(self.ext._write_full_csv(export_path))
        raw = read_raw(export_path)
        self.assertIn('# Total Requests: 8', raw)
        self.assertIn('# Total Requests Logged: 8', raw)

        header, rows = read_csv_rows(export_path)
        self.assertEqual(len(rows), 8)

        # rows are keyed by serial number (col 0), assigned in response order
        by_serial = dict((int(row[0]), row) for row in rows)
        self.assertEqual(sorted(by_serial), [1, 2, 3, 4, 5, 6, 7, 8],
                         'serials must be unique and contiguous 1..8')

        # expected (Host, Method, URL, Status, Tool, ReqCount, InsertionPoints)
        # in the exact order responses were delivered
        expected = [
            ('ginandjuice.shop', 'GET',  'https://ginandjuice.shop/home',        '200', 'Proxy',    '1', '0'),
            ('ginandjuice.shop', 'GET',  'https://ginandjuice.shop/home',        '200', 'Proxy',    '2', '0'),
            ('ginandjuice.shop', 'POST', 'https://ginandjuice.shop/login',       '302', 'Repeater', '1', '2'),
            ('ginandjuice.shop', 'POST', 'https://ginandjuice.shop/login',       '401', 'Repeater', '2', '2'),
            ('ginandjuice.shop', 'GET',  'https://ginandjuice.shop/item?id=1',   '500', 'Intruder', '1', '1'),
            ('ginandjuice.shop', 'GET',  'https://ginandjuice.shop/search?q=1,2','200', 'Scanner',  '1', '1'),
            ('ginandjuice.shop', 'GET',  'https://ginandjuice.shop/timeout',     '-',   'Proxy',    '1', '0'),
            ('ginandjuice.shop', 'GET',  'https://ginandjuice.shop/error',       'Error','Proxy',   '1', '1'),
        ]
        timestamp = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')
        for serial, want in enumerate(expected, start=1):
            row = by_serial[serial]
            host, method, url, status, tool, count, ip = want
            self.assertEqual(row[1], host,   'row %d host' % serial)
            self.assertEqual(row[2], method, 'row %d method' % serial)
            self.assertEqual(row[3], url,    'row %d url (comma URL must survive)' % serial)
            self.assertEqual(row[4], status, 'row %d status' % serial)
            self.assertEqual(row[5], tool,   'row %d tool' % serial)
            self.assertEqual(row[6], count,  'row %d request count' % serial)
            self.assertEqual(row[7], ip,     'row %d insertion points' % serial)
            self.assertTrue(timestamp.match(row[8]), 'row %d start time' % serial)
            self.assertTrue(timestamp.match(row[9]), 'row %d end time' % serial)
            self.assertLessEqual(row[8], row[9],
                                 'row %d start must not be after end' % serial)


if __name__ == '__main__':
    unittest.main(verbosity=2)
