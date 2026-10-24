# MCP conditional diagnostic acceptance status

The three required terminal classes remain incomplete. No native or complete
ACC-014 pass has been established. R01 and R02 failed checks are retained.

The controller rejected R02's legacy unbound diagnostic arms, Windows
`ctypes.string_at` stimulus (which can become a Python `OSError`), and its
custom known Python exception labeled unknown. The current source candidate
requires an initialized run, exact PID/birth/config, current Job membership,
nonce and a bounded expiry. Legacy two-field arms do not select diagnostics.
The native candidate uses fixed `RaiseFailFastException`, tested only across
an OS ABI model. Its real Windows exit/monitor/dump path is unverified.

No-stack suppression cannot erase an existing fallback. Arming after a
previous managed stack snapshot is rejected as proof of unavailable stacks.
An early, correctly bound stimulus and the full managed lifecycle still need
integration. The original incident preparer distinguishes absent stacks from
cached-only stacks and never grants a managed dump target after the Job ends.

An honest unknown-cause stimulus remains unsupported. The implementation does
not create an exception saying its cause is unknown. Original observations,
independent localization, recovery, and the entire central ACC-014 matrix
remain required. A local arm or a synthetic dump cannot grant those outcomes.

The current targeted tests exercise admission, wrong/stale identity, native
ABI calling convention, existing fallback protection, original incident
preparation and original dump parsing. They are source/OS fixture evidence;
the previously failing complete MCP suite remains unresolved.
