"""The R47 PktMon status and owner gate, without native capture operations."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_suite as suite


OWNER = (r'E:\FakeNet-NG-MCP-test-work\scenario-suite-20260912'
         r'\0ce24ebdba9b-sst-012-a1\run-01\pktmon.etl')
REAL = (Path(__file__).parent / 'fixtures/pktmon-r47-active-zh.txt').read_bytes().decode('utf-8')
ENGLISH = ("Collected data:\n    Packet counters, packet capture\n"
           "Capture type:\n    All packets\nLogging parameters:\n"
           "    Logger name: PktMon\n    Log file: " + OWNER + "\n"
           "    Maximum file size: 1024 MB\n")


@pytest.mark.parametrize(('status', 'exit_code', 'owner', 'expected'), [
    (REAL, 0, OWNER, True),
    (ENGLISH, 0, OWNER, True),
    (REAL, 1, OWNER, False),
    ('', 0, OWNER, False),
    ('Running', 0, OWNER, False),
    ('unknown\n' + REAL, 0, OWNER, False),
    ('数据包监视器没有运行。\n' + REAL, 0, OWNER, False),
    ('Not Running\n' + ENGLISH, 0, OWNER, False),
    (REAL.replace(OWNER, OWNER + '.other'), 0, OWNER, False),
    (REAL, 0, OWNER + '.other', False),
    (REAL + '    日志文件: ' + OWNER + '.other\n', 0, OWNER, False),
    (REAL.replace('记录程序名称:        PktMon', '记录程序名称: Other'), 0, OWNER, False),
    (REAL.replace('数据包计数器，数据包捕获', '无'), 0, OWNER, False),
    (REAL.replace('数据包计数器，数据包捕获', '无') + '\n历史: 数据包捕获', 0, OWNER, False),
    (REAL.replace('所有数据包', '无'), 0, OWNER, False),
    (REAL.replace('日志文件:           ' + OWNER, '日志文件:           ' + OWNER + '.other')
     + '\n历史: ' + OWNER, 0, OWNER, False),
    (REAL.replace('最大文件大小:      1024 MB', ''), 0, OWNER, False),
    (REAL, 0, '', False),
    (ENGLISH.replace('Log file: ' + OWNER, 'Log file: ' + OWNER + '.other'), 0, OWNER, False),
])
def test_shared_pktmon_owner_status(status, exit_code, owner, expected):
    assert suite.Suite._shared_pktmon_owner_active(status, exit_code, owner) is expected


def test_windows_equivalent_case_and_separator_only():
    assert suite.Suite._shared_pktmon_owner_active(REAL, 0, OWNER.lower().replace('\\', '/'))
    assert not suite.Suite._shared_pktmon_owner_active(REAL, 0, r'E:\Wrong\pktmon.etl')


def test_shared_launch_command_checks_owner_before_process_create():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    runner.guest_work_root = suite.E_GUEST_WORK_ROOT
    runner.native_clock_diagnostic = False
    runner.identity = type('Identity', (), {'candidate_id': 'candidate'})()
    runner._start_kernel_capture = lambda root: {'session_name': 'owned-kernel'}
    commands = []
    runner._vm_json = lambda command, timeout: (commands.append(command) or
        ({'guest': r'E:\scope\run-02', 'run_label': 'run-02', 'pid': 1,
          'probe_creation_ticks': 123, 'etl': OWNER,
          'pktmon_nic': r'E:\scope\run-01\pktmon-nic.json',
          'physical_owner_id': 'nonce:pktmon', 'nonce': 'nonce',
          'capture_run_id': 'nonce:run-02',
          'probe': r'E:\scope\run-02\probe.jsonl'}, '{}'))
    owner = {'run_label': 'run-01', 'etl': OWNER,
             'pktmon_nic': r'E:\scope\run-01\pktmon-nic.json',
             'physical_owner_id': 'nonce:pktmon'}
    runner._start_probe_on_shared_capture(r'E:\scope', {
        'bucket': 'B1', 'tempo': 'normal', 'variant': 'v',
        'interleave': 'restart-window', 'cadence_ms': 100,
        'connection_window_seconds': 10,
        'probe_target': {'host': 'test.local', 'port': 80, 'protocol': 'tcp'}
    }, 'nonce', 'run-02', owner)
    command = commands[0]
    assert command.index('physical owner files absent') < command.index('Test-SharedPktMonOwner')
    assert command.index('Test-SharedPktMonOwner') < command.index('Invoke-CimMethod')
    assert "physical pktmon owner not running" in command


def test_unknown_response_recovery_rejects_foreign_owner_without_cleanup():
    runner = suite.Suite.__new__(suite.Suite)
    runner._stop_capture_and_probe = lambda capture: pytest.fail('foreign writer stopped')
    status = REAL.replace(OWNER, OWNER + '.other')
    recovered = runner._reconcile_capture_start({
        'identity_match': True,
        'value': {'probe_ready': {'pid': 123, 'creation_ticks': 456},
                  'etl_exists': True, 'pktmon_exit': 0, 'pktmon_status': status}
    }, {'session_name': 'retained'}, r'E:\scope\run-02', OWNER,
       r'E:\scope\run-01\pktmon-nic.json', 'nonce', 'run-02', 'nonce:pktmon')
    assert recovered is None


def test_unknown_response_recovery_requires_owner_file_without_cleanup():
    runner = suite.Suite.__new__(suite.Suite)
    runner._stop_capture_and_probe = lambda capture: pytest.fail('writer stopped without ETL')
    recovered = runner._reconcile_capture_start({
        'identity_match': True,
        'value': {'probe_ready': {'pid': 123, 'creation_ticks': 456},
                  'etl_exists': False, 'pktmon_exit': 0, 'pktmon_status': REAL}
    }, {'session_name': 'retained'}, r'E:\scope\run-02', OWNER,
       r'E:\scope\run-01\pktmon-nic.json', 'nonce', 'run-02', 'nonce:pktmon')
    assert recovered is None
