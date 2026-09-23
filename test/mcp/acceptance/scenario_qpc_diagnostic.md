# Native QPC diagnostic entry (T009)

This is a read-only diagnostic for a **new** case captured with
`scenario_suite.py --native-clock-diagnostic`. The normal suite path and its
strict UTC fault verdict are unchanged. The switch adds boot/process identity
to pktmon capture metadata and probe ready/process_ready; the fault action
records the same identity before and after closure. `capture_run_id` is made
before the managed start; the case connects it to the later managed `run_id`
through nonce, candidate, native tuple and hashed original files.

On the verified Win10 x64 guest, after the suite has finalized its case and
originals, invoke the single entry with a **new** output directory:

```powershell
& 'C:\Python313\python.exe' 'E:\diagnostic\scenario_qpc_diagnostic.py' --case 'E:\evidence\evidence\sst-002\attempt-01\fault-evidence-result.case.json' --evidence-root 'E:\evidence' --output 'E:\evidence\qpc-diagnostic-01'
```

Transfer `scenario_qpc_diagnostic.py`, `scenario_qpc_identity.py`,
`etl_raw_clock.py`, `tdh_metadata.py`, `scenario_tcpip.py`,
`scenario_clock.py`, and `sst_fault_evidence.py` together. The entry reuses
T007 R02's two-pass raw/default ETL exporter and TDH property reader. It
requires exact non-time payload pairing, one binary selector for each selected
connect/accept and **every** same-generation terminal (including bound tuple
terminals), TDH Tcb/endpoint/process semantics, complete count and unchanged
input hashes. Ambiguous or missing records produce `INCOMPLETE`, with a
manifest and no accepted diagnostic interval. Output consists of
`manifest.json`, `raw/{manifest,raw,default,paired}.json*`, `selectors.json`,
and `tdh/{manifest,metadata}.json*`. It does not modify the case or original
fault result and never asserts an ACC pass.

The TDH semantic gate checks the actual TCPIP provider, event descriptor and
task name against the verified Win10 dialect. Establishment requires nonzero
PID and ProcessStartKey; same-TCB nonzero identity must remain stable. The
verified `TcpCloseTcbRequest` may report PID and ProcessStartKey both zero:
that pair has no process attribution and remains a terminal of the anchored
TCB. Transitions compare TDH OldState/NewState with the native text; only
verified state codes are admitted. Unknown tasks or state codes leave the
diagnostic incomplete until their dialect is independently verified.

`BootIdentifier` is the GUID from private Native API
`NtQuerySystemInformation(SystemBootEnvironmentInformation=90)`. The
32-byte Win10 x64 layout is accepted only with status 0 and return length 32;
raw bytes, GUID, firmware type and flags are retained. The ETL header's
`BootTime` is a separate FILETIME and **must not** be compared to the GUID.
The class/layout comes from [System Informer phnt ntexapi.h](https://github.com/winsiderss/phnt/blob/master/ntexapi.h),
not a stable public Microsoft API. The documented
[GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)
and [QPC](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter)
provide creation FILETIME and counter samples. Unsupported API/layout/boot
facts remain explicit diagnostics, with no guessed BCD boot GUID.
