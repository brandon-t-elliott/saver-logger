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
writes real files the tests can parse back.

## What the tests demonstrate

Every test asserts *correct* behavior, so on the unfixed `main` branch the
suite fails in exactly the places the fix branches address:

| Test | Expected on `main` | Fixed by branch |
|------|--------------------|-----------------|
| `test_smoke_extension_loads` | pass | — (sanity) |
| `test_per_url_request_count_increments` | pass | — (sanity) |
| `test_worker_processes_queued_messages_end_to_end` | pass | — (characterization for `performance`) |
| `test_concurrent_requests_keep_their_own_data` | **FAIL** | `fix-request-correlation` |
| `test_out_of_order_responses_keep_their_own_data` | **FAIL** | `fix-request-correlation` |
| `test_in_flight_requests_keep_tracking_entries` | **FAIL** | `fix-request-correlation` |
| `test_tracking_entries_die_with_their_messages` | pass¹ | `fix-request-correlation` (WeakHashMap redesign; **red on that branch** until it lands) |
| `test_csv_preserves_commas_in_fields` | **FAIL** | `csv-integrity` |
| `test_csv_formula_injection_neutralized` | **FAIL** | `csv-integrity` |
| `test_csv_footer_records_burp_version` | **FAIL** | `csv-integrity` |
| `test_export_failure_closes_file_handle` | **FAIL** | `csv-integrity` |
| `test_unload_saves_queued_messages` | **FAIL** | `reliability-fixes` |
| `test_auto_backup_survives_missing_folder` | **FAIL** | `reliability-fixes` |

In addition to the bug-demonstration tests above, the suite carries twelve
functional characterization tests that pass on every branch and pin the
extension's main behaviors: complete log-row metadata (all ten columns),
serial-number ordering, the `-` and `Error` status fallbacks, CSV
header/footer structure, empty-export handling, UTF-8 round-trips, manual
`Backup Now`, auto-backup's single-overwritten-file contract, `Clear Logs`
state reset, worker resilience to a malformed message, and backup-scheduler
interval/enable configuration.

¹ Passes on `main` only as a side effect of the overwrite bug (the tracking
dict never grows past ~1 entry because concurrent requests clobber the same
key — the very defect the correlation tests fail on). Together with the
in-flight test it pins the lifetime contract of the keyed design: an entry
lives exactly as long as its message (in-flight requests always keep their
data; abandoned messages are reclaimed with the object). CPython's reference
counting makes the eviction deterministic in tests; the JVM's GC is lazier
but provides the same reachability guarantee.

## Testing a fix branch

From this branch, overlay a fix branch's extension code, run the suite, then
restore:

```bash
git checkout <fix-branch> -- SAVER_LOGGER.py
python3 tests/test_saver_logger.py
git checkout HEAD -- SAVER_LOGGER.py && git restore --staged SAVER_LOGGER.py
```

## Limitations

The harness exercises the extension's logic, not Burp itself. In particular,
the correlation fix assumes Burp passes the **same** `IHttpRequestResponse`
instance for a message's request and response events; the mocks mirror that
assumption rather than prove it. Verifying it needs a live Burp session
against a slow endpoint (e.g. a several-second delay) and a check that
Start Time differs from End Time in the export. If the assumption fails in a
given Burp version, the fix degrades gracefully: insertion points are computed
from the request at response time and Start Time falls back to End Time —
never another request's data.
