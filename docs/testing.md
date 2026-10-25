> Consolidated inventory, original procedures, verdict rules and known gaps: [Acceptance catalog](acceptance/README.md). This inventory is not a new runtime pass.
>
> S1 offline loop (2026-10-22): the catalog is v2 and `tools/acceptance.py` adds `plan --mode full|selected|stress`, `execute` and `judge --results`. Only statically reviewed offline pytest cases run on the host; every native case stays `blocked` until the S2 adapters and real VM/endpoints exist. Commands, candidate/environment files, exit codes and exclusions are in [Acceptance README](acceptance/README.md). `test.py` also accepts `--results <path>` and `--non-interactive`, and now exits non-zero when a case fails.
>
> S2 native adapter code (2026-10-22, partial): `tools/acceptance_native.py` registers fixed-argv drivers and fixed sub-check tables for upstream/egress/reviewed-IPv4/process-redirect; Multihost, Windows/Linux PCAP functional modes, headless policy/payload, MCP P01-P04/SPECIAL, Linux mode and manual features remain explicitly blocked. No native execution was performed; see the acceptance README.

# FakeNet-NG Test Plan
This test plan informs developers how to quality assure FakeNet-NG by using two
test suites:
* Automated Test Suite
* Manual Test Suite

If you just want to know how to test FakeNet-NG, see the following sections:
* Dev and Test Setup
* Using `test.py`
* Automated Test Suite
* Manual Test Suite

For brief highlights of why things are the way they are, read straight through.

## Testing Needs
FakeNet-NG has numerous features and specifications that are sometimes mutually
exclusive. Adding and testing new FakeNet features while a configuration
setting is in one disposition can lead to unanticipated failure when that
setting is changed.

FakeNet manipulates the network, so most network-based test control
mechanisms may be difficult to configure/coordinate with FakeNet's features,
and unreliable in cases where FakeNet fails (or even potentially in cases
where it behaves as designed).

Consequently, the bulk of testing is currently automated by interactively
executing the test script `test/test.py`. Several features are too complicated
to incorporate into a script and must be tested manually.

## Dev and Test Setup
It is recommended to use at least a Linux VM and a Windows VM for development
and testing.

The Linux guest should have at least two network interfaces. This is necessary
for testing that the `LinuxRestrictInterface` feature has not been broken by
recent changes. It also may be convenient to leave one interface connected to
NAT to reduce time spent switching networks between pushing changes versus
testing.

Meanwhile, the Windows guest should have git installed even if that is not
where development takes place, for convenience in pulling down updated branches
for testing. Note that on Windows, FakeNet has to be installed via `setup.py`
for the test script (`test.py`) to use the latest changes.

It is easiest to avoid false test results and troubleshooting issues if both
guests are tested on a host-only network as opposed to having access to the
public Internet.

### Using the Windows Guest to Test Linux MultiHost Operation
To use the Windows test machine to test Linux `MultiHost` mode, the Windows
machine must use the FakeNet-NG host as its gateway and DNS server.

On Windows:
* Run the Network Connections control panel (`ncpa.cpl`)
* Right-click on the network adapter and click `Properties`
* Select `Internet Protocol Version 4 (TCP/IPv4)`
* Click the `Advanced...` button
* In the IP Settings tab under Default gateways, click `Add...` (or `Edit...`
  if a gateway is already defined)
    * In the `TCP/IP Gateway Address` dialog, enter the IP address of the
      FakeNet machine
    * Leave `Automatic metric` alone
    * Click the `Add` button
* In the DNS tab, click `Add...`
    * In the `TCP/IP DNS Server` dialog, enter the IP address of the FakeNet
      machine again
    * Click Add
* Save all the settings by clicking `OK`
* Ping the FakeNet IP to ensure connectivity
* Commence testing

Note that you will need to copy automatically generated configuration files to
the FakeNet machine during testing. For details, see the section titled "Using
`test.py`".

## Using test.py

### Test Script Dependencies
The test script requires dependencies over and above what FakeNet calls for. As
of this writing, they include:
* `irc`
* `requests`
* `icmplib`

Install these dependencies using `requirements.txt` in the `test` folder:
```
pip install -r requirements.txt
```

### Test Script Usage
FakeNet supports Internet simulation for the local machine (i.e. in
`SingleHost` mode) and by acting as the gateway and DNS server for a remote
machine (i.e. `MultiHost` mode). For a handful of tests, the test script needs
to know the IP address where FakeNet is running and in what `NetworkMode`.
Consequently, the test script requires you to specify a `<where>` parameter.
You can specify either the literal word `here` to test locally, or a
dot-decimal IP address to test remotely:

```
Usage: test.py <where> [matchspec1 [matchspec2 [...] ] ]

Valid where:
  here
  Any dot-decimal IP address

Each match specification is a regular expression that
will be compared against test names, and any matches
will be included. Because regular expression negative
matching is complicated to use, you can just prefix
a match specification with a minus sign to indicate
that you would like to include only tests that do NOT
match the expression.
```

Optional tooling flags, which do not change the positional/match semantics:

```text
test.py here --results /path/to/results.tsv --non-interactive --multihost-ready
```

`--results` writes a `status<TAB>name<TAB>detail` file. A case that fails on the
first attempt and passes on the retry is written as `FAIL` with both attempts in
the detail; the process exits non-zero for any failure or retry-only success.
`--non-interactive` suppresses the MultiHost "type ok" prompt, but it is
accepted only together with `--multihost-ready`; without that explicit readiness
input the affected MultiHost suite fails instead of assuming the remote system
is ready. A stop failure or stop exception is also recorded as a case failure
and makes the process exit non-zero.

If you are testing remotely the test script will create a custom configuration
file for each subsuite of tests that it runs. You must copy that configuration
to the place where FakeNet is running and launch FakeNet specifying that config
file using the `-c` argument. This is done for you when testing locally.

The test script also allows positive and negative matching rules in order to
include or exclude tests.

Some of this may duplicate `pytest` functionality. If someone can refactor this
into `pytest`, that is fine, but the current script serves.

### Test Script Idiosynchrasies
The salient peculiarity of `test.py` is that on Windows it requires you to
install FakeNet and it then runs the global `fakenet.exe` script entry point
available via the Windows path environment variable; and on Linux, it executes
`python -m fakenet.fakenet` directly. Alas, this is for purely undocumented and
forgettable reasons. It shouldn't be too difficult to make these consistent if
that becomes important to someone.

## Detailed Test Plan
Testing in only one configuration leads to quality issues. If you wish to merge
code to master, your code must pass tests in all the combinations described
here.


### Jargon
A test suite specifies a series of tests that must be completed.

By and large, specific features subject to testing are called out by the name
of the corresponding configuration setting name in FakeNet's configuration file
schema. Otherwise, they may be specified by the corresponding entry in the
[FakeNet-NG Software Requirements Specification (SRS)](srs.md).

If a setting name is ambiguous among multiple INI-style `[sections]`, it can be
disambiguated in dot format, e.g. `Diverter.ProcessBlacklist` to specify the
global process blacklist rather than the listener-specific setting
`<Listener>.ProcessBlacklist`.

Completely testing a setting indicates testing against every disposition the
setting may take (e.g. enabled, disabled).

Where settings may be omitted entirely or left empty, their disposition can be
called "unconfigured". The opposing disposition is referred to as "configured".

Where features are to be tested "against" or "versus" some other factor, it
means testing all setting values against all dispositions for each factor. For
example:

`RedirectAllTraffic` *versus* destination IP *versus* port disposition

Means testing the following feature and factor dispositions:
* `RedirectAllTraffic` feature:
    * Enabled
    * Disabled
* Destination IP factor (what IP is the test hitting?):
    * External IP - IP of the host running FakeNet
    * Arbitrary host - arbitrary IP
    * Named host - IP returned by FakeNet DNS Listener in response to a DNS A
      request
    * Localhost (if in SingleHost mode) - In practice, 127.0.0.1
* Port disposition factor (is there a listener here?):
    * Bound - A FakeNet listener is bound to the destination port under test
    * Unbound - No FakeNet listener is bound to the destination port under test

This would amount to 2 x 4 x 2 = 16 total tests.

Tests such as the above may be subdivided to indicate which sets of
dispositions are handled together or apart.

### Test Dimensions
FakeNet-NG supports two (2) platforms:
* Windows
* Linux

FakeNet-NG supports two operating modes via the `NetworkMode` configuration
setting:
* `SingleHost` (both platforms)
* `MultiHost` (Linux only as of this writing)

Notably, `Auto` is not a distinct `NetworkMode`; it selects `SingleHost` on
Windows and `MultiHost` on Windows.

In `MultiHost` mode, FakeNet only expressly supports clients running Windows
operating systems. Optionally testing with clients running Linux may pose an
opportunity to proactively discover more issues.

Hence, FakeNet must be tested in the following combinations of platforms,
modes, and clients:

| FakeNet platform | `NetworkMode` | Test Client | Client platform | Note     |
|------------------|---------------|-------------|-----------------|----------|
| Windows          | `SingleHost`  | (Local)     | (Windows)       |          |
| Linux            | `SingleHost`  | (Local)     | (Linux)         |          |
| Linux            | `MultiHost`   | Remote      | Windows         |          |
| Linux            | `MultiHost`   | Remote      | Linux           | Optional |

In each combination, FakeNet must be tested against the full range of
applicable tests in the Automated Test Suite provided by the test script
`test/test.py`. It should be noted that some tests are expected to output
errors such as socket errors even when the tests are successful.

As of this writing, the Manual Test Suite must also be executed if the FakeNet
feature set is to be fully exercised for quality assurance of a given release.

### Automated Test Suite
Run `test/test.py` against the FakeNet instance.

#### Automated Test Subsuites
The Automated Test Suite contains the following automated test subsuites and
tests.

The "No Redirect" subsuite tests:
* `RedirectAllTraffic = No` vs. destination IP vs. port disposition

The "Global process blacklist" subsuite tests:
* Only in `SingleHost` mode:
    * `Diverter.ProcessBlacklist` configured

The "Global process whitelist" subsuite tests:
* Only in `SingleHost` mode:
    * `Diverter.ProcessWhitelist` configured

The "General" subsuite tests:
* TCP listener vs. destination IP vs. port disposition
* UDP listener vs. destination IP vs. port disposition
* ICMP external IP
* ICMP arbitrary host
* ICMP domain name
* DNS listener
* HTTP listener
* HTTP listener `Custom` response versus URI/hostname/negative
* FTP listener
* POP3 listener
* SMTP listener
* SMTP SSL listener
* IRC listener
* Proxy listener and port unbound
* Proxy listener and port bound and listener `Hidden`
* `HostBlackList`
* `BlackListPortsTCP` - Redirection Blacklisting
* `BlackListPortsUDP` - Redirection Blacklisting
* `BlackListIDsICMP` - Redirection Blacklisting
* Only in `SingleHost` mode:
    * `<Listener>.ProcessBlacklist` configured - Redirection Blacklisting
    * `<Listener>.ProcessWhitelist` configured - Redirection Blacklisting
    * `<Listener>.HostBlacklist` configured - Redirection Blacklisting
    * Incorrect test as of this writing: `<Listener>.HostWhitelist` configured
* Hidden versus unproxied (exposed) listeners via listener setting `Hidden`

### Manual Test Suite
The following significant features either need tests added to the automated
suite, or must be tested manually.

#### Manual Test Subsuites
The "Manual Forever" Subsuite includes features that likely will always have to
be tested manually:
* `LinuxRestrictInterface` - FakeNet-NG Interface Restriction in `MultiHost`
  mode

The "Manual But Shouldn't Be" Subsuite includes features that should definitely
have tests added to the automated suite when possible:
* `ExecuteCmd` configured
* Microsoft NCSI support

The "Manual Low-Priority" Subsuite includes lower-priority items should
probably also have tests added to the automated test suite when time permits:
* Running and testing each listener in standalone mode as its own Python script
* Control-C Terminates Gracefully
* IPC Halt Control
* Linux Flush IP Tables Control
* Diverter Enable/Disable
* Syslog logging
* Packet Capture Enable/Disable
* Packet Capture Filename Specification
* ICMP Traffic Logging
* `LinuxFlushIptables`
* `LinuxFlushDNSCommand` - DNS Resolver Cache Flush Control
* `FixGateway`
* `FixDNS`
* `ModifyLocalDNS` - Local DNS Modification
* `StopDNSService` (Windows only) - DNS Resolver Cache Termination
* HTTP CustomResponse `<RAW-DATE>` replacement
* Black and White List Mutual Exclusivity

### Features Inherently Tested
Several important FakeNet-NG features are exercised inherently by adhering to
the test plan. These include, but are not limited to:
* Diverter `NetworkMode` Configuration
* Foreign-Bound Traffic Redirection

### Known and Suspected Deficiencies in FakeNet and its Tests
The following native results remain historical until they are re-run on the
current candidate in S2; the test-side defects were fixed on 2026-10-22:

* `SMTP SSL listener test`: the function previously referenced an undefined
  `server` and passed positional arguments that the current `SMTP_SSL` exposes
  only as keyword-only. It now uses the current keyword API, verifies the
  `sendmail` refusal mapping (full/partial refusal is not success), returns
  `True` only after a successful send, and lets construction/send errors
  propagate. Its native listener result is still NOT_RUN.
* `IRC listener test` (works on Linux, not on Windows).
* `Listener host whitelist`: the test previously targeted the blacklist port
  8082, and the fixture used `6.6.6.6`, which is also the global
  `Diverter.HostBlackList`. It now targets port 8083 with `9.9.9.9` and adds a
  blocked negative; the positive case is no longer shadowed by the global
  blacklist. Its native result is still NOT_RUN.
* A stop failure or stop exception now enters the suite failure and the
  process exit code; it is no longer only logged.
* The functional status of process blacklisting on Linux is indeterminate: it
  was thought to have been deficient, however it may have been observed
  passing the tests in the automated test suite.

## Contained offline acceptance profiles

`CORE-WINDOWS-OFFLINE`, `MCP-UNIT-PRODUCT`, and `MCP-UNIT-TOOLING` keep
`collection_safe: false` for ordinary environments. Their finite profiles are
`wine-contained-v1` and `linux-contained-v1`. The existing `plan`, `execute`,
and `judge` entry points all recheck the same profile and source bindings.
An environment boolean cannot grant collection permission.

The operator supplies `collection_profile` with `kind`, `attestation`, and
`sha256`. The attestation is a read-only controller original directly under
`/run-control`, bound to the current Docker instance, fixed image, exact source
snapshot, interpreter, dependencies, and `/out` workspace. The process also
observes non-root execution, zero capabilities, no-new-privileges, loopback-only
networking, and read-only root/source/control mounts before permitting code.
The controller obtains the instance and image from the real Docker inspection;
copying another run's attestation or changing the selected modules refuses it.
The Windows profile uses an owned copy of the image's installed Wine prefix
with the repository's exact offline `pydivert==2.1.0` wheel. It earns offline
Wine evidence only, never WinDivert/Windows native or full-regression credit.

For each profile, use the existing CLI with a source candidate and the bound
environment file, then independently judge the original results:

```text
python tools/acceptance.py plan --mode selected --case MCP-UNIT-PRODUCT --case MCP-UNIT-TOOLING --candidate candidate.json --environment linux-contained.json --output /out/linux/plan.json
python tools/acceptance.py execute --plan /out/linux/plan.json
python tools/acceptance.py judge --plan /out/linux/plan.json --results /out/linux/results --output /out/linux/independent-summary.json
```

Run the Windows case with its Wine interpreter profile in a separate plan in
that same owned container. Preserve all raw attempts and stop owned resources
after judging; unqualified environments continue to report these cases blocked.


## Repeat the three contained offline cases

From the repository's project Python environment, use the central entry:

```text
python tools/acceptance.py contained-offline
python tools/acceptance.py contained-offline --profile linux
python tools/acceptance.py contained-offline --profile wine --output Logs/acceptance/my-fresh-run
```

This finite preset needs Linux uid 1000, the existing pinned Docker image, and
the repository's existing `.venv-mcp-runners` interpreter. It never pulls or
builds an image. Run from a committed checkout: source bytes must match HEAD.
Each invocation creates a fresh owned container and a unique `Logs/acceptance`
run, measures its CID/image/mounts, and generates the source/interpreter-bound
attestation and environment files. Wine preparation copies the image's installed
prefix and installs only the exact local pydivert 2.1.0 wheel into that copy.
No per-run CID, hash, environment JSON, or receipt needs to be filled by hand.

The original plan/execute/independent-judge chain remains authoritative. `run.json`
links its selected summaries, records exact command output and owned cleanup,
and always keeps native/full credit false. Exit 0 requires selected offline
success and cleanup; preparation, test, judge, timeout, or cleanup failure exits
nonzero and preserves all attempts. Existing output directories are refused.
The default false collection guards remain active outside these measured profiles.
The preset does not deploy a package or execute Windows/Linux native tests.


## Read-only MCP endpoint observations

The central MCP runner keeps the complete original endpoint snapshots and raw
recovery diff. For P01-ENTRY, ACC-002, ACC-016 and ACC-005 only, it can attribute
a changed host-only ephemeral UDP endpoint to a preexisting foreign process.
This requires unchanged state/version/config/controller and service instance,
no accepted or unknown mutation, identical process PID/birth/image/hash in both
bounded observations, and an exact owner match in the original raw netstat row.
Managed or WinDivert owners, TCP, low ports, wildcard/loopback addresses and
other environment differences keep the original strict recovery failure.

The independent oracle derives this classification again from recorded raw
observations; a summary flag cannot grant it. Old traces without owner proof
remain failed. Mutating units retain the original recovery conditions. Benign
fixture tests exercise the original consumer and independent replay; they do
not establish native owner collection or a full Windows/P02 regression pass.


## MCP service restart identity

P02 runs the original controller, race, replay and cache-reset assertions.
The adapter binds the original helper's ProgramFiles expression to the frozen
installation root, including PowerShell literal escaping. Its SCM/image and
PID/birth checks remain active. STOPPED, GONE and STARTED text alone cannot
establish a restart: the trace must prove the bound old PID/birth has exited
and a running candidate instance has a different birth with the same image,
hash and service settings before advancing the operation epoch. Independent
replay repeats these checks. Missing proof, an unchanged instance or a foreign
image fails; old failed traces and unresolved mutation flags remain unchanged.


State versions are monotonic within a verified service instance. A proven
old-process exit and new birth starts a new epoch whose first actual status
sets its initial version. Recovery checks every epoch's accepted-operation
chain and requires the final version to match; same-epoch regression, missing
steps, duplicate acceptance, unexplained advances and unknown responses still
fail. The benign restart fixture starts a new Coordinator with NULL config
and version 1, matching the installed service instead of preloading default.


The same observer covers the original `configure_fault_service` and controlled
restart helper calls. It records the old process exit and stopped SCM state,
then verifies the new candidate image, hash, later birth and exact requested
fault-mode/grace changes. Other settings must remain unchanged. A reused helper
instance keeps its epoch; a missing status/version anchor cannot create one.
Direct stop operations retain their original behavior.

Helper references imported by original consumers during a unit are restored
when the unit exits, along with already loaded consumer references. This keeps
independent replay bound to its own session instead of a previous unit's
transport. The oracle repeats the original helpers over the recorded OS and
HTTP responses, including their refusal paths.

Restoring fault settings can itself restart the service and clear its loaded
configuration. The runner validates the operation chain before that restart,
then restores an originally bound configuration only after a proved owned
helper reset to NULL with no intervening accepted load. It checks the final
configuration, version ledger, service settings and OS audit against the actual
last process. Unproved configuration disappearance and unknown mutations still
fail. A benign original initialization-failure test exercises both helper
restarts, real NULL resets, final configuration restoration and independent
replay. Source/fixture success does not grant native Windows or full-regression
credit, and does not turn an observed product failure into a pass.


Original ACC007 abrupt crash and ACC008 controlled snapshot restarts use their
own existing recovery consumers. The adapter records the candidate process and
settings before the fixed owned stop/crash. It advances the ledger only after
the unchanged original tree, canary, marker and startup audit checks establish
the old exit/recovery responsibility and the new instance. The actual candidate
image/hash, later birth and unchanged settings are checked again around the
new status/version anchor. Snapshot cases keep their original expected failed
or stopped state; a failed snapshot is never normalized into a pass.

The benign process and snapshot fixtures reset version/config/cache for each
new process. Independent replay rejects altered raw exit, image, birth,
settings or anchor evidence. A no-op helper and an unknown mutation cannot
create a verified epoch. After a final owned restart clears configuration, only
the original bound identity may be restored, then the final state and complete
per-instance operation ledger are checked. These fixture checks remain source
validation; native execution and its cleanup must be observed separately.


SCM start completion can precede the service's own startup recovery. The original
helper observer uses the original read-only `wait_state` for at most 60 seconds
until `recovering` ends, then requires a stopped service with no run and a valid
version. It verifies the same candidate process and settings again around this
observation. This wait does not repeat the helper restart or change configuration;
a timeout, failed startup, changed instance or missing version still fails. The
startup fixture exposes a recovering observation before stopped and checks that
exactly one helper restart occurred.


The service can accept an internal `protective_stop` after a managed-process
failure. It consumes a real Coordinator version even though no client submitted
that command. The runner accounts for this step only from recorded read-only
proof: the same candidate PID/birth/image/settings, the original owned run and
config, the cleared marker, ordered acceptance/completion events without gaps
or reset, and completed command-cache receipts under the original controller.
Event epochs and cache epochs are separate domains; each is checked against its
own observation, and both are bracketed by the same candidate process. The owned
start receipt must match its cached original exactly. A command-name prefix or
an unexplained version difference cannot establish an accepted operation.

The proof is captured before another mutation or process replacement can lose
the original cache/marker. Independent replay derives the internal ledger step
again from raw OS/HTTP responses. Missing, foreign, stale, reordered, incomplete
or conflicting proofs and unknown responses keep the original failure. Tests
use the real Coordinator internal submission, EventLog and cache, and reject
nine classes of altered proof. This observer never submits a protective stop,
replays a mutation or changes the service's recovery behavior.


The fixed process-scope PowerShell helper keeps the held GetProcess handle and
its full FILETIME as the authoritative identity. CIM CreationDate has only
microsecond precision, so its cross-representation check compares the exact
microsecond quantum while retaining every 100ns digit in the returned identity.
A second held GetProcess observation must match the complete PID, FILETIME and
image; either exited handle, missing CIM identity, image mismatch or a different
microsecond is rejected. This is not a general timestamp tolerance.

`NativePinPrecisionTests` runs the unchanged shared helper against 17 local API
boundary cases on Windows PowerShell, without opening, creating or terminating
a real target process. Ubuntu marks that test skipped. The source validation
also executes the same cases in the existing VM channel and separately pins the
verified current candidate read-only; neither probe grants the five original
native acceptance cases a pass.
