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
| `test_tracking_dict_stays_bounded` | pass¹ | `fix-request-correlation` |
| `test_tracking_dict_capped_under_burst` | pass¹ | `fix-request-correlation` (size-cap hardening; **red on that branch** until it lands) |
| `test_csv_preserves_commas_in_fields` | **FAIL** | `csv-integrity` |
| `test_csv_formula_injection_neutralized` | **FAIL** | `csv-integrity` |
| `test_csv_footer_records_burp_version` | **FAIL** | `csv-integrity` |
| `test_export_failure_closes_file_handle` | **FAIL** | `csv-integrity` |
| `test_unload_saves_queued_messages` | **FAIL** | `reliability-fixes` |
| `test_auto_backup_survives_missing_folder` | **FAIL** | `reliability-fixes` |

¹ These pass on `main` only as a side effect of the overwrite bug (the
tracking dict never grows past ~1 entry because concurrent requests clobber
the same key — the very defect the two correlation tests fail on). They pin
the bounded-memory properties that the keyed design must maintain: stale
entries get purged, and a burst arriving faster than the stale cutoff is
still size-capped.

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
