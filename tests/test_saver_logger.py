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
    """One HTTP message event. Burp does NOT guarantee the same
    IHttpRequestResponse instance for a message's request and response events,
    so tests can build two MockMessage objects that share a request payload to
    model that. `getRequest()` returns that payload (unique per request unless
    shared), which is how the extension correlates the two events."""

    _seq = 0

    def __init__(self, url, host='ginandjuice.shop', method='GET',
                 param_count=0, status=200, response_payload='RESPONSE-BYTES',
                 request_payload=None):
        if request_payload is None:
            MockMessage._seq += 1
            request_payload = 'REQ-%d %s' % (MockMessage._seq, url)
        self.request_info = MockRequestInfo(url, method, param_count)
        self._status = status
        self._service = MockHttpService(host)
        self._responded = False
        self._response_payload = response_payload
        self._request_payload = request_payload

    def getRequest(self):
        return self._request_payload

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

    def bytesToString(self, data):
        # Burp's helper turns request/response byte[] into a String; the mock's
        # payloads are already strings.
        return data if isinstance(data, str) else str(data)


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


class CountingLock(object):
    """Wraps a lock and counts acquisitions, so a test can assert how many
    separate lock holds a method takes."""

    def __init__(self, inner):
        self.inner = inner
        self.acquires = 0

    def lock(self):
        self.acquires += 1
        self.inner.lock()

    def unlock(self):
        self.inner.unlock()


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

    def _capture_dialogs(self):
        """Record the text of JOptionPane.showMessageDialog calls."""
        self._dialogs = []
        SAVER_LOGGER.JOptionPane.showMessageDialog = staticmethod(
            lambda panel, message, *a: self._dialogs.append(message))

    def _restore_dialogs(self):
        if hasattr(SAVER_LOGGER.JOptionPane, 'showMessageDialog'):
            try:
                delattr(SAVER_LOGGER.JOptionPane, 'showMessageDialog')
            except AttributeError:
                pass

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

    def test_in_flight_requests_are_logged_and_tracked(self):
        """Every in-flight request is logged immediately and keeps a pending
        tracking entry until its response fills the row in."""
        messages = [MockMessage('https://ginandjuice.shop/inflight/%d' % i,
                                param_count=1)
                    for i in range(1500)]
        for msg in messages:
            self.ext._handle_request(4, msg)

        self.assertEqual(len(self.ext.log_data), 1500,
                         'every request is logged immediately')
        self.assertEqual(len(self.ext.request_tracking), 1500,
                         'every in-flight request keeps a pending entry')

        for msg in messages:
            self._respond(msg)
        self.assertEqual(len(self.ext.request_tracking), 0,
                         'entries are removed once the response fills the row')
        self.assertEqual(len(self.ext.log_data), 1500,
                         'responses update rows, they do not add new ones')

    def test_identical_concurrent_requests_correlate_fifo(self):
        """Two identical in-flight requests (same request content) are each
        logged, and their responses fill in the two rows oldest-first - no
        duplicate row, and no request left without its response."""
        content = 'GET /dup HTTP/1.1\r\nHost: ginandjuice.shop\r\n\r\n'
        r1 = MockMessage('https://ginandjuice.shop/dup', param_count=1,
                         request_payload=content)
        r2 = MockMessage('https://ginandjuice.shop/dup', param_count=1,
                         request_payload=content)
        self.ext._handle_request(4, r1)
        self.ext._handle_request(4, r2)
        self.assertEqual(len(self.ext.log_data), 2, 'both requests logged')

        resp1 = MockMessage('https://ginandjuice.shop/dup', param_count=1,
                            status=200, request_payload=content)
        resp2 = MockMessage('https://ginandjuice.shop/dup', param_count=1,
                            status=500, request_payload=content)
        resp1._responded = True
        resp2._responded = True
        self.ext._handle_response(4, resp1)
        self.ext._handle_response(4, resp2)

        self.assertEqual(len(self.ext.log_data), 2,
                         'responses update the two rows, no duplicates')
        self.assertEqual(sorted(row[4] for row in self.ext.log_data),
                         ['200', '500'], 'both responses were applied')
        self.assertEqual(len(self.ext.request_tracking), 0,
                         'no pending entries remain')

    def test_response_on_different_message_object_updates_row(self):
        """Burp does not guarantee the same IHttpRequestResponse instance for
        a message's request and response events. When the response arrives on
        a different object, it must still fill in the request's row (matched by
        host/method/URL) rather than append a duplicate.

        Reproduces the reported bug: the request is logged once (pending) and
        again with the response, giving two rows for one request.
        """
        req_msg = MockMessage('https://ginandjuice.shop/reused', method='GET',
                              param_count=2, status=200)
        self.ext._handle_request(4, req_msg)
        self.assertEqual(len(self.ext.log_data), 1, 'request logged once')

        # A DISTINCT object for the response event that carries the same
        # request content (as Burp's response messageInfo does).
        resp_msg = MockMessage('https://ginandjuice.shop/reused', method='GET',
                               param_count=2, status=200,
                               request_payload=req_msg.getRequest())
        resp_msg._responded = True
        self.ext._handle_response(4, resp_msg)

        self.assertEqual(len(self.ext.log_data), 1,
                         'the response must update the request row, not add a '
                         'duplicate')
        row = self.ext.log_data[0]
        self.assertEqual(row[4], '200', 'status filled in on the request row')
        self.assertNotEqual(row[9], '-', 'end time filled in on the request row')

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

    # ---------- concurrency / robustness fixes ---------- #

    def test_request_is_logged_immediately_with_pending_response(self):
        """Every request is logged as its own row as soon as it is seen, with
        placeholder status/end time, so a request whose response never arrives
        is still recorded. The response then fills in that same row."""
        timestamp = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')
        msg = MockMessage('https://ginandjuice.shop/pending', method='POST',
                          param_count=2, status=200)
        self.ext._handle_request(4, msg)

        self.assertEqual(len(self.ext.log_data), 1,
                         'the request must be logged before any response')
        row = self.ext.log_data[0]
        self.assertEqual(row[0], 1)                              # Serial No
        self.assertEqual(row[2], 'POST')                        # Method
        self.assertEqual(row[3], 'https://ginandjuice.shop/pending')
        self.assertEqual(row[4], '-')                           # Status pending
        self.assertEqual(row[COL_INSERTION_POINTS], 2)          # from the request
        self.assertTrue(timestamp.match(row[8]))               # Start Time set
        self.assertEqual(row[9], '-')                           # End Time pending

        # The response fills in status and end time on the SAME row.
        msg._responded = True
        self.ext._handle_response(4, msg)

        self.assertEqual(len(self.ext.log_data), 1,
                         'the response must update the row, not append a new one')
        row = self.ext.log_data[0]
        self.assertEqual(row[4], '200')
        self.assertTrue(timestamp.match(row[9]))

    def test_request_appends_row_under_single_lock(self):
        """The serial increment and row append happen under one data_lock
        hold, so a concurrent Clear Logs cannot orphan a stale-serial row."""
        spy = CountingLock(self.ext.data_lock)
        self.ext.data_lock = spy

        msg = MockMessage('https://ginandjuice.shop/atomic', param_count=1)
        self.ext._handle_request(4, msg)

        self.assertEqual(spy.acquires, 1,
                         'serial assignment and row append must be a single '
                         'atomic data_lock section')
        self.assertEqual(len(self.ext.log_data), 1)
        self.assertEqual(self.ext.log_data[0][0], 1)

    def test_response_without_matching_request_uses_fallback(self):
        """A response with no prior request event is still logged, with
        insertion points recomputed from the request and start time falling
        back to the end time - never another request's data."""
        msg = MockMessage('https://ginandjuice.shop/orphan', param_count=3,
                           status=200)
        msg._responded = True
        self.ext._handle_response(4, msg)  # no _handle_request first

        self.assertEqual(len(self.ext.log_data), 1)
        row = self.ext.log_data[0]
        self.assertEqual(row[COL_INSERTION_POINTS], 3,
                         'insertion points must be recomputed from the request')
        self.assertEqual(row[8], row[9],
                         'start time falls back to end time when unmatched')

    def test_backup_now_with_no_data_reports_no_data(self):
        """Demonstrates: Backup Now with an empty log must say there is no
        data, not report a false 'Backup failed' error, and must not write a
        file."""
        self._capture_dialogs()
        try:
            self.ext.backup_now(None)
        finally:
            self._restore_dialogs()

        joined = ' '.join(self._dialogs).lower()
        self.assertIn('no data', joined,
                      'empty backup must report no data: %r' % self._dialogs)
        self.assertNotIn('failed', joined,
                         'empty backup must not report a failure: %r' % self._dialogs)
        backups = [n for n in os.listdir(self.tmp)
                   if n.startswith('SAVER_LOGGER_BACKUP_')]
        self.assertEqual(backups, [], 'no file should be written with no data')

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
        # Distinct message objects for the request and response events, sharing
        # the same request content - mirroring that Burp may hand the two
        # events different IHttpRequestResponse instances.
        self.request_msg = MockMessage(url, host=host, method=method,
                                       param_count=params, status=status)
        response_payload = 'MALFORMED' if kind == 'malformed' else 'RESPONSE-BYTES'
        self.response_msg = MockMessage(url, host=host, method=method,
                                        param_count=params, status=status,
                                        response_payload=response_payload,
                                        request_payload=self.request_msg.getRequest())
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
        # Transactions in the order their requests are delivered. Rows are
        # logged at request time, so this is also the serial-number order.
        self._request_order = []

    def tearDown(self):
        self.ext.shutdown_flag = True
        if self.ext.worker_thread:
            self.ext.worker_thread.join(2000)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---------- delivery helpers ---------- #

    def _send_request(self, txn):
        self._request_order.append(txn)
        self.ext.processHttpMessage(txn.tool_flag, True, txn.request_msg)

    def _send_response(self, txn):
        # A dropped connection fires a response event with no body.
        txn.response_msg._responded = (txn.kind != 'dropped')
        self.ext.processHttpMessage(txn.tool_flag, False, txn.response_msg)

    def _deliver(self, txns, mode):
        """Deliver a phase of transactions. Rows are logged at request time,
        so serial numbers follow the order requests are delivered (recorded in
        self._request_order); responses fill in status/end time afterwards.

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

    def _await_settled(self, expected, timeout=15):
        """Wait until at least `expected` rows exist and every row has had its
        response applied (End Time no longer the pending placeholder)."""
        pending = SAVER_LOGGER.BurpExtender.PENDING
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.ext.data_lock.lock()
            try:
                ends = [row[C_END] for row in self.ext.log_data]
            finally:
                self.ext.data_lock.unlock()
            if len(ends) >= expected and all(end != pending for end in ends):
                return
            time.sleep(0.02)
        self.fail('session did not settle %d rows before timeout (have %d)' %
                  (expected, len(self.ext.log_data)))

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
        master (request-delivery) order."""
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
                         'exactly one logged row per request')
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

        # Phase 1 + 2
        self._deliver(phase_seq, 'sequential')
        self._deliver(phase_batched, 'batched')

        # Mid-session checkpoint: a manual backup must capture, line for line,
        # exactly what has been logged so far. Rows are logged at request time,
        # so serials follow request-delivery order (self._request_order).
        checkpoint = len(phase_seq) + len(phase_batched)
        self._await_settled(checkpoint)
        master_so_far = list(self._request_order)
        self.assertEqual(len(master_so_far), checkpoint)
        self._assert_log_matches(master_so_far)
        self.ext.backup_now(None)
        backups = [n for n in os.listdir(self.tmp)
                   if n.startswith('SAVER_LOGGER_BACKUP_')]
        self.assertEqual(len(backups), 1, 'Backup Now must write one file')
        self._assert_export_matches(os.path.join(self.tmp, backups[0]),
                                    master_so_far)

        # Phase 3 + specials
        self._deliver(phase_concurrent, 'concurrent')
        self._deliver(specials, 'concurrent')

        self._await_settled(len(self._request_order))
        master = list(self._request_order)

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

        self._request_order = []  # track the fresh session on its own
        fresh = self._build_bulk(6)
        self._deliver(fresh, 'sequential')
        self._await_settled(len(fresh))
        fresh_master = list(self._request_order)
        self._assert_log_matches(fresh_master)  # serials restart at 1, counts fresh

        fresh_path = os.path.join(self.tmp, 'fresh.csv')
        self.assertTrue(self.ext._write_full_csv(fresh_path))
        self._assert_export_matches(fresh_path, fresh_master)


if __name__ == '__main__':
    unittest.main(verbosity=2)
