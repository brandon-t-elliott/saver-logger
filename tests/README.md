# SAVER_LOGGER test harness

Logic tests for the extension, runnable with plain CPython — no Burp, no JVM,
and **no network traffic** (the Burp API is fully mocked; fixture URLs are
inert strings; the only I/O is CSV files written to a temp directory).

## Running

```bash
python3 tests/test_saver_logger.py
```

`tests/java_stubs.py` installs stand-ins for the `burp`, `javax.swing`,
`java.awt`, `java.io`, `java.nio`, `java.util` and `java.lang` modules before
`SAVER_LOGGER.py` is imported. Swing/AWT widgets are inert dummies (the UI is
not under test); the `java.io` classes are functional so `_write_full_csv`
writes real files the tests parse back.

## What the suite covers

The suite is **29 tests**, each asserting correct behavior of the extension's
logic. By area:

| Area | Tests | What they verify |
|------|-------|------------------|
| Request logging & correlation | `test_request_is_logged_immediately_with_pending_response`, `test_request_appends_row_under_single_lock`, `test_concurrent_requests_keep_their_own_data`, `test_out_of_order_responses_keep_their_own_data`, `test_in_flight_requests_are_logged_and_tracked`, `test_response_on_different_message_object_updates_row`, `test_identical_concurrent_requests_correlate_fifo`, `test_response_without_matching_request_uses_fallback` | Every request is logged immediately (pending `-` status/end until its response), then the response fills in that same row — matched by **request content**, so it works even when Burp delivers the request and response events on different `IHttpRequestResponse` objects, with many requests in flight, out of order, or identical (FIFO); a response never duplicates a request, and a response with no request at all is still logged |
| CSV integrity | `test_csv_preserves_commas_in_fields`, `test_csv_formula_injection_neutralized`, `test_csv_footer_records_burp_version`, `test_export_failure_closes_file_handle`, `test_unicode_fields_survive_export`, `test_export_writes_metadata_and_column_header`, `test_export_with_no_data_returns_false` | RFC 4180 encoding preserves field data verbatim, spreadsheet formula triggers are neutralized, UTF-8 round-trips, the header/footer/column structure is correct (footer records the full Burp version), the output stream is closed on a mid-export failure, and an empty log exports nothing |
| Concurrency / robustness | `test_worker_processes_queued_messages_end_to_end`, `test_worker_survives_processing_errors` | The background worker drains the queue end to end and survives a malformed message (serial assignment and row append atomicity is covered by `test_request_appends_row_under_single_lock` above) |
| Reliability | `test_unload_saves_queued_messages`, `test_auto_backup_survives_missing_folder`, `test_backup_scheduler_configuration` | Messages queued at unload are flushed into the exit backup; a missing backup folder is created instead of failing silently; the scheduler honors the configured interval and enable/disable |
| Logging & metadata | `test_smoke_extension_loads`, `test_per_url_request_count_increments`, `test_logged_row_records_message_metadata`, `test_serial_numbers_increment_in_log_order`, `test_missing_response_logged_with_placeholder_status`, `test_unparseable_response_logged_with_error_status` | A logged row carries the right values in all ten columns, serials increment in order, per-URL counts build up, and missing / unparseable responses log `-` and `Error` |
| Backup & Clear Logs | `test_backup_now_creates_timestamped_backup`, `test_backup_now_with_no_data_reports_no_data`, `test_auto_backup_uses_single_overwritten_file`, `test_clear_logs_resets_memory_but_keeps_exported_files` | Manual backup writes one timestamped file (and reports "no data" rather than a false failure when the log is empty); auto-backup overwrites a single file; Clear Logs resets in-memory state but leaves already-exported files on disk untouched |
| End-to-end | `test_full_session_is_logged_and_exported_correctly` | A full multi-tool session, verified per row (see below) |

### End-to-end session test

`EndToEndSessionTest.test_full_session_is_logged_and_exported_correctly`
drives a large, realistic session entirely through the real public entry
point (`processHttpMessage` -> queue -> background worker), then exports it
and reads the CSV back to verify **every logged row and every exported line,
column by column**. The session spans all seven tools, every HTTP method, a
wide range of status codes, and ~70 transactions delivered sequentially, in
out-of-order concurrent batches, and fully concurrently (all in flight at
once). It covers repeated URLs whose request counts build up, URLs bearing
commas / semicolons / quotes / non-ASCII, a host crafted for CSV formula
injection, dropped connections (`-` status) and unparseable responses
(`Error` status), a mid-session backup checkpoint, and a post-Clear-Logs
fresh session that confirms state resets while on-disk exports survive. The
mocks deliver each transaction's request and response events on **different**
message objects that share the request content, mirroring that Burp does not
guarantee the same `IHttpRequestResponse` instance for both — so the E2E
exercises (and would catch a regression in) content-based correlation.

## Limitations

The harness exercises the extension's logic, not Burp itself. The correlation
matches a response to its request by **request content** (which Burp preserves
on both events), so it does not depend on object identity. It still assumes
the request bytes are identical across the two events; verifying end-to-end
behavior needs a live Burp session against a slow endpoint (e.g. a
several-second delay) to confirm rows start pending and are filled in when the
response arrives. Two genuinely identical in-flight requests share a
correlation key and are filled in oldest-first; their responses may attach to
the sibling row, which is immaterial for identical requests.
