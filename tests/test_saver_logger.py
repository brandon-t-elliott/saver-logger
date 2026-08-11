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


# Burp ITool flag constants -> display names, for the simulated session
SESSION_TOOLS = [
    (4, 'Proxy'), (8, 'Spider'), (16, 'Scanner'), (32, 'Intruder'),
    (64, 'Repeater'), (128, 'Sequencer'), (1024, 'Extender'),
]
SESSION_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
SESSION_STATUSES = [200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 503]

# Repeated (path, insertion-point count) pairs so per-URL request counts build
# up over the session. Full URLs repeat exactly, so the URL column matches.
SESSION_URLS = [
    ('/', 0),
    ('/login?next=/home', 2),
    ('/search?q=test', 1),
    ('/cart', 0),
    ('/api/users?id=1', 1),
    ('/api/orders?id=1&status=open', 2),
    ('/products?category=books', 1),
    ('/checkout', 3),
    ('/account/settings', 0),
    ('/api/cart/items?id=42', 1),
]
TIMESTAMP_RE = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')

# Column indexes in a logged row / exported CSV line
C_SERIAL, C_HOST, C_METHOD, C_URL, C_STATUS = 0, 1, 2, 3, 4
C_TOOL, C_COUNT, C_INSERTION, C_START, C_END = 5, 6, 7, 8, 9


class Transaction(object):
    """One request/response pair in the simulated session, carrying both the
    mock message and the values its logged row must contain."""

    def __init__(self, url, host, method, tool_flag, tool_name,
                 params, status, kind='normal'):
        payload = 'MALFORMED' if kind == 'malformed' else 'RESPONSE-BYTES'
        self.msg = MockMessage(url, host=host, method=method,
                               param_count=params, status=status,
                               response_payload=payload)
        self.url = url
        self.host = host
        self.method = method
        self.tool_flag = tool_flag
        self.tool_name = tool_name
        self.params = params
        self.status = status
        self.kind = kind          # 'normal' | 'dropped' | 'malformed'
        self.formula_host = False  # set for the CSV-injection case

    @property
    def expected_status(self):
        if self.kind == 'dropped':
            return '-'
        if self.kind == 'malformed':
            return 'Error'
        return str(self.status)


class EndToEndSessionTest(unittest.TestCase):
    """Drive a large, realistic multi-tool Burp session through the real
    public entry point (processHttpMessage -> queue -> background worker) and
    verify every logged row and every exported CSV line, one at a time.

    The session spans all seven tools, every HTTP method, a wide range of
    status codes, ~70 transactions delivered sequentially, in concurrent
    batches, and fully concurrently (all in flight at once) with out-of-order
    responses, repeated URLs whose request counts build up, URLs bearing
    commas / semicolons / quotes / non-ASCII, a host crafted for CSV formula
    injection, dropped connections ('-' status) and unparseable responses
    ('Error' status). It also checkpoints a mid-session backup and, after a
    Clear Logs, runs a fresh session to confirm state resets cleanly while
    on-disk exports survive.

    Because it verifies correlation and CSV integrity for every single row,
    it is red on main and green only once every fix branch is applied - one
    check that the whole system works together.
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

    # ---------- delivery helpers ---------- #

    def _send_request(self, txn):
        self.ext.processHttpMessage(txn.tool_flag, True, txn.msg)

    def _send_response(self, txn):
        # A dropped connection fires a response event with no body.
        txn.msg._responded = (txn.kind != 'dropped')
        self.ext.processHttpMessage(txn.tool_flag, False, txn.msg)

    def _deliver(self, txns, mode):
        """Deliver a phase of transactions. Responses are always enqueued in
        list order, so serial numbers follow the master transaction order
        regardless of how requests are interleaved.

        mode 'sequential'  - request then response, one at a time
             'batched'     - batches of 5: all requests (scrambled), then
                             all responses (in order) => out-of-order arrival
             'concurrent'  - all requests first (every txn in flight at once),
                             then all responses in order
        """
        if mode == 'sequential':
            for txn in txns:
                self._send_request(txn)
                self._send_response(txn)
        elif mode == 'batched':
            for start in range(0, len(txns), 5):
                batch = txns[start:start + 5]
                for txn in reversed(batch):
                    self._send_request(txn)
                for txn in batch:
                    self._send_response(txn)
        elif mode == 'concurrent':
            for txn in txns:
                self._send_request(txn)
            for txn in txns:
                self._send_response(txn)
        else:
            raise ValueError('unknown delivery mode: %s' % mode)

    def _await_rows(self, expected, timeout=15):
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

    def _confirm_yes(self):
        SAVER_LOGGER.JOptionPane.YES_OPTION = 0
        SAVER_LOGGER.JOptionPane.showConfirmDialog = staticmethod(lambda *a: 0)

    def _restore_confirm(self):
        for name in ('YES_OPTION', 'showConfirmDialog'):
            if hasattr(SAVER_LOGGER.JOptionPane, name):
                delattr(SAVER_LOGGER.JOptionPane, name)

    # ---------- session construction ---------- #

    def _build_bulk(self, count):
        """Generate `count` varied transactions cycling through tools,
        methods, statuses and repeated URLs, sprinkling in dropped and
        malformed responses."""
        txns = []
        for i in range(count):
            path, params = SESSION_URLS[i % len(SESSION_URLS)]
            method = SESSION_METHODS[i % len(SESSION_METHODS)]
            tool_flag, tool_name = SESSION_TOOLS[i % len(SESSION_TOOLS)]
            status = SESSION_STATUSES[i % len(SESSION_STATUSES)]
            kind = 'normal'
            if i % 17 == 16:
                kind = 'dropped'
            elif i % 19 == 18:
                kind = 'malformed'
            txns.append(Transaction('https://ginandjuice.shop' + path,
                                    'ginandjuice.shop', method,
                                    tool_flag, tool_name, params, status, kind))
        return txns

    def _build_specials(self):
        """Edge-case transactions: tricky URLs, a formula-injection host, and
        explicit dropped / malformed cases."""
        specials = [
            Transaction('https://ginandjuice.shop/search?q=1,2,3',
                        'ginandjuice.shop', 'GET', 16, 'Scanner', 1, 200),
            Transaction('https://ginandjuice.shop/list?a=1;b=2;c=3',
                        'ginandjuice.shop', 'GET', 4, 'Proxy', 1, 200),
            Transaction('https://ginandjuice.shop/q?name="admin"',
                        'ginandjuice.shop', 'GET', 64, 'Repeater', 1, 200),
            Transaction(u'https://ginandjuice.shop/café?drink=\U0001f378',
                        'ginandjuice.shop', 'GET', 4, 'Proxy', 1, 200),
            Transaction('https://ginandjuice.shop/api/ping',
                        '=2+5+cmd|" /C calc"!A0', 'GET', 1024, 'Extender', 0, 200),
            Transaction('https://ginandjuice.shop/download/report.pdf',
                        'ginandjuice.shop', 'GET', 4, 'Proxy', 0, 200,
                        kind='dropped'),
            Transaction('https://ginandjuice.shop/api/broken',
                        'ginandjuice.shop', 'POST', 32, 'Intruder', 3, 200,
                        kind='malformed'),
        ]
        specials[4].formula_host = True
        return specials

    def _expected(self, master):
        """(serial, txn, per-URL request count) for each transaction, in
        master (response) order."""
        counts = {}
        out = []
        for serial, txn in enumerate(master, start=1):
            counts[txn.url] = counts.get(txn.url, 0) + 1
            out.append((serial, txn, counts[txn.url]))
        return out

    # ---------- per-line verification ---------- #

    def _assert_logged_row(self, row, serial, txn, count):
        """Verify one in-memory log row, column by column. In memory the host
        is stored verbatim - formula-injection escaping happens only at
        export - so the raw host is expected here."""
        where = 'serial %d (%s)' % (serial, txn.url)
        self.assertEqual(row[C_SERIAL], serial, '%s serial' % where)
        self.assertEqual(row[C_HOST], txn.host, '%s host' % where)
        self.assertEqual(row[C_METHOD], txn.method, '%s method' % where)
        self.assertEqual(row[C_URL], txn.url, '%s url' % where)
        self.assertEqual(row[C_STATUS], txn.expected_status, '%s status' % where)
        self.assertEqual(row[C_TOOL], txn.tool_name, '%s tool' % where)
        self.assertEqual(row[C_COUNT], count, '%s request count' % where)
        self.assertEqual(row[C_INSERTION], txn.params,
                         '%s insertion points' % where)
        self.assertTrue(TIMESTAMP_RE.match(str(row[C_START])),
                        '%s start time %r' % (where, row[C_START]))
        self.assertTrue(TIMESTAMP_RE.match(str(row[C_END])),
                        '%s end time %r' % (where, row[C_END]))
        self.assertLessEqual(row[C_START], row[C_END], '%s start after end' % where)

    def _assert_log_matches(self, master):
        """Every in-memory row, in order, one line at a time."""
        self.assertEqual(len(self.ext.log_data), len(master),
                         'exactly one logged row per response')
        for i, (serial, txn, count) in enumerate(self._expected(master)):
            self._assert_logged_row(self.ext.log_data[i], serial, txn, count)

    def _assert_exported_line(self, row, serial, txn, count):
        """Verify one parsed CSV line, column by column. At export the host
        is formula-guarded, but every other field must round-trip exactly."""
        where = 'line serial %d (%s)' % (serial, txn.url)
        self.assertEqual(len(row), 10, '%s must have 10 columns' % where)
        self.assertEqual(int(row[C_SERIAL]), serial, '%s serial' % where)
        if txn.formula_host:
            self.assertFalse(row[C_HOST].startswith(('=', '+', '-', '@')),
                             '%s host must be neutralized: %r' % (where, row[C_HOST]))
            self.assertEqual(row[C_HOST].lstrip("'"), txn.host,
                             '%s host must round-trip after the guard' % where)
        else:
            self.assertEqual(row[C_HOST], txn.host, '%s host' % where)
        self.assertEqual(row[C_METHOD], txn.method, '%s method' % where)
        self.assertEqual(row[C_URL], txn.url,
                         '%s url must survive export unmodified' % where)
        self.assertEqual(row[C_STATUS], txn.expected_status, '%s status' % where)
        self.assertEqual(row[C_TOOL], txn.tool_name, '%s tool' % where)
        self.assertEqual(int(row[C_COUNT]), count, '%s request count' % where)
        self.assertEqual(int(row[C_INSERTION]), txn.params,
                         '%s insertion points' % where)
        self.assertTrue(TIMESTAMP_RE.match(row[C_START]), '%s start time' % where)
        self.assertTrue(TIMESTAMP_RE.match(row[C_END]), '%s end time' % where)
        self.assertLessEqual(row[C_START], row[C_END], '%s start after end' % where)

    def _assert_export_matches(self, export_path, master):
        """Every exported CSV line, one at a time, plus file structure."""
        raw = read_raw(export_path)
        self.assertIn('# Total Requests: %d' % len(master), raw)
        self.assertIn('# Total Requests Logged: %d' % len(master), raw)

        header, rows = read_csv_rows(export_path)
        self.assertEqual(header,
                         ['Serial No', 'Host', 'Request Method', 'URL',
                          'Status Code', 'Tool Name', 'Request Count',
                          'Insertion Point Count', 'Start Time', 'End Time'])
        # One physical data line per transaction: no row split or merged by a
        # stray comma / newline in the data.
        self.assertEqual(len(rows), len(master),
                         'exported data-line count must equal transaction count')

        by_serial = dict((int(row[C_SERIAL]), row) for row in rows)
        self.assertEqual(sorted(by_serial), list(range(1, len(master) + 1)),
                         'serials must be unique and contiguous')
        for serial, txn, count in self._expected(master):
            self._assert_exported_line(by_serial[serial], serial, txn, count)

    # ---------- the session ---------- #

    def test_full_session_is_logged_and_exported_correctly(self):
        bulk = self._build_bulk(63)
        specials = self._build_specials()

        phase_seq = bulk[0:15]       # simple back-to-back traffic
        phase_batched = bulk[15:39]  # concurrent batches, out-of-order responses
        phase_concurrent = bulk[39:63]  # everything in flight at once
        # master response order == delivery order of the phases below
        master = phase_seq + phase_batched + phase_concurrent + specials

        # Phase 1 + 2
        self._deliver(phase_seq, 'sequential')
        self._deliver(phase_batched, 'batched')

        # Mid-session checkpoint: a manual backup must capture, line for line,
        # exactly what has been logged so far.
        checkpoint = len(phase_seq) + len(phase_batched)
        self._await_rows(checkpoint)
        self._assert_log_matches(master[:checkpoint])
        self.ext.backup_now(None)
        backups = [n for n in os.listdir(self.tmp)
                   if n.startswith('SAVER_LOGGER_BACKUP_')]
        self.assertEqual(len(backups), 1, 'Backup Now must write one file')
        self._assert_export_matches(os.path.join(self.tmp, backups[0]),
                                    master[:checkpoint])

        # Phase 3 + specials
        self._deliver(phase_concurrent, 'concurrent')
        self._deliver(specials, 'concurrent')

        self._await_rows(len(master))
        time.sleep(0.1)  # let the worker settle; no extra rows should appear

        # Line-by-line verification of the entire in-memory log.
        self._assert_log_matches(master)

        # Every tool, method, and status family must actually be represented.
        self.assertEqual(set(row[C_TOOL] for row in self.ext.log_data),
                         set(name for _, name in SESSION_TOOLS),
                         'all seven tools must appear in the log')
        self.assertTrue(set(SESSION_METHODS).issubset(
                            set(row[C_METHOD] for row in self.ext.log_data)),
                        'every HTTP method must appear in the log')
        statuses = set(row[C_STATUS] for row in self.ext.log_data)
        self.assertIn('-', statuses, 'a dropped response must be logged')
        self.assertIn('Error', statuses, 'an unparseable response must be logged')

        # Full export round-trip, line by line.
        export_path = os.path.join(self.tmp, 'session.csv')
        self.assertTrue(self.ext._write_full_csv(export_path))
        self._assert_export_matches(export_path, master)
        exported_session = read_raw(export_path)

        # --- Clear Logs, then a fresh session ---
        self._confirm_yes()
        try:
            self.ext.clear_logs(None)
        finally:
            self._restore_confirm()

        self.assertEqual(self.ext.log_data, [], 'clear must empty the log')
        self.assertEqual(self.ext.request_counter, 0, 'clear must reset serials')
        self.assertTrue(os.path.exists(export_path),
                        'Clear Logs must not delete exported files')
        self.assertEqual(read_raw(export_path), exported_session,
                         'exported file must be unchanged by a clear')

        fresh = self._build_bulk(6)
        self._deliver(fresh, 'sequential')
        self._await_rows(len(fresh))
        self._assert_log_matches(fresh)  # serials restart at 1, counts fresh

        fresh_path = os.path.join(self.tmp, 'fresh.csv')
        self.assertTrue(self.ext._write_full_csv(fresh_path))
        self._assert_export_matches(fresh_path, fresh)


if __name__ == '__main__':
    unittest.main(verbosity=2)
