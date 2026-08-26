# -*- coding: utf-8 -*-
"""One-click GUI VM acceptance runner (plan v1.14 §12.18).

Start via Run-Tests.cmd (self-elevates).  Fully unattended afterwards:
the elevated fakenet launch skips the UAC prompt because the runner
itself is elevated, and shutdown uses fakenet's own -f stop flag.

Evidence levels per item (printed and recorded in results.tsv):
  实测    - exercised live on this machine
  等效    - deterministic code path exercised (real UI event cannot be
            automated, e.g. clicking "No" on a UAC prompt)
Exit codes: 0 = all PASS, 1 = any FAIL, 2 = REFUSED (precondition).
"""

import os
import json
import re
import shutil
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from fakenet.gui import configmodel, launcher, validator  # noqa: E402

EXIT_PASS, EXIT_FAIL, EXIT_REFUSED = 0, 1, 2
RESULTS = []
LOG_DIR = None
_GUI_LOGS_BEFORE = {}
FNPR_NONCE = None
CORE_STARTED_MARKER = 'FakeNet-NG started successfully'
CORE_FAILURE_MARKERS = (
    'Traceback (most recent call last):',
    'FakeNet-NG terminated with an error',
    'FakeNet-NG stop failed',
)


def evaluate_start_log(content):
    """Return whether core log evidence proves a successful startup."""
    if any(marker in content for marker in CORE_FAILURE_MARKERS):
        return False, '核心日志记录异常终止'
    exit_codes = re.findall(r'FakeNet-NG exiting: rc=([^\s]+)', content)
    if any(code != '0' for code in exit_codes):
        return False, '核心进程以非零状态退出'
    if CORE_STARTED_MARKER not in content:
        return False, '核心日志缺少成功启动标记'
    return True, '核心日志已记录成功启动'


def evaluate_stop_log(content):
    """Return whether core log evidence proves stop-flag shutdown with rc=0."""
    started, detail = evaluate_start_log(content)
    if not started:
        return False, detail
    if 'Stop flag found at ' not in content:
        return False, '核心日志未记录 stop flag 命中'
    if 'Stopping...' not in content:
        return False, '核心日志未记录停止阶段'
    exit_codes = re.findall(r'FakeNet-NG exiting: rc=([^\s]+)', content)
    if not exit_codes or exit_codes[-1] != '0':
        return False, '核心日志未记录 rc=0 正常退出'
    return True, 'stop flag 已触发且核心 rc=0 正常退出'


def read_core_log(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as handle:
            return handle.read()
    except OSError:
        return ''


def startup_log_decided(path):
    content = read_core_log(path)
    return (
        CORE_STARTED_MARKER in content or
        any(marker in content for marker in CORE_FAILURE_MARKERS) or
        'FakeNet-NG exiting: rc=' in content
    )


def result(name, status, detail, level='实测'):
    line = '%s\t%s\t%s\t[%s]' % (status, name, detail, level)
    print(line, flush=True)
    RESULTS.append((status, name, detail, level))
    if LOG_DIR:
        with open(os.path.join(LOG_DIR, 'results.tsv'), 'a',
                  encoding='utf-8') as handle:
            handle.write(line + '\n')


def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:  # noqa: BLE001 - non-Windows
        return False


def refuse(detail):
    result('前置条件', 'REFUSED', detail, '实测')
    print('\nREFUSED: %s' % detail)
    return EXIT_REFUSED


def wait_for(predicate, timeout, interval=1.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def find_file(name, extra_candidates=()):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, name),
        os.path.join(script_dir, '..', name),
        os.path.join(REPO, name),
        os.path.join(REPO, 'build_gui_dist', name),
        os.path.join(REPO, 'dist', name),
    ] + list(extra_candidates)
    for candidate in candidates:
        candidate = os.path.abspath(candidate)
        if os.path.isfile(candidate):
            return candidate
    return None


def build_smoke_config(path):
    """Minimal non-invasive config via the GUI's own writer: no traffic
    diversion, no PCAP, a single raw listener.  Proves writer + validator
    + real fakenet agreement on this machine."""
    model = configmodel.ConfigModel.new_config()
    model.fakenet().set('DivertTraffic', 'No')
    diverter = model.diverter()
    diverter.set('DumpPackets', 'No')
    diverter.set('RedirectAllTraffic', 'No')
    diverter.delete('DefaultTCPListener')
    diverter.delete('DefaultUDPListener')
    model.delete_section('ProxyTCPListener')
    model.delete_section('ProxyUDPListener')
    # new_config now provisions HTTPListener80/443 content listeners
    # (plan 2026.08.21-01 I6); the minimal smoke config stays minimal.
    model.delete_section('HTTPListener80')
    model.delete_section('HTTPListener443')
    sec = model.ensure_section('RawTCPListener')
    sec.set('Enabled', 'True')
    sec.set('Port', '1337')
    sec.set('Protocol', 'TCP')
    sec.set('Listener', 'RawListener')
    sec.set('UseSSL', 'No')
    sec.set('Timeout', '10')
    sec.set('Hidden', 'False')
    errors = [i for i in validator.validate(model)
              if i.level == validator.ERROR]
    if errors:
        return model, errors
    model.mtime = None
    model.save(path)
    return model, errors


def gui_logs_root():
    """Package-root Logs directory written by fakenet-GUI.exe, if any."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(script_dir, '..', '..'))
    logs = os.path.join(root, 'Logs')
    return logs if os.path.isdir(logs) else None


def snapshot_gui_logs(logs_root=None):
    """{name: mtime} of GUI logs before the run; used to copy only files
    this acceptance session created or touched (v1.23 §12.26)."""
    logs = logs_root if logs_root is not None else gui_logs_root()
    if not logs or not os.path.isdir(logs):
        return {}
    snapshot = {}
    for name in os.listdir(logs):
        if name.endswith('.log'):
            try:
                snapshot[name] = os.path.getmtime(os.path.join(logs, name))
            except OSError:
                pass
    return snapshot


def active_fakenet_images():
    """Read-only leftover check; passing runs never hide state with taskkill."""
    active = []
    for image in ('fakenet-GUI.exe', 'fakenet.exe'):
        try:
            proc = subprocess.run(
                ['tasklist.exe', '/FI', 'IMAGENAME eq %s' % image,
                 '/FO', 'CSV', '/NH'], capture_output=True, text=True,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except OSError:
            continue
        if proc.returncode == 0 and image.lower() in (proc.stdout or '').lower():
            active.append(image)
    return active


def request_gui_close():
    """Post WM_CLOSE to every top-level window owned by the formal GUI."""
    script = (
        "Add-Type -TypeDefinition @'\n"
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "public static class FakenetWindowClose {\n"
        "  public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);\n"
        "  [DllImport(\"user32.dll\")]\n"
        "  public static extern bool EnumWindows(EnumWindowsProc callback, "
        "IntPtr lParam);\n"
        "  [DllImport(\"user32.dll\")]\n"
        "  public static extern uint GetWindowThreadProcessId(IntPtr hWnd, "
        "out uint processId);\n"
        "  [DllImport(\"user32.dll\", SetLastError=true)]\n"
        "  [return: MarshalAs(UnmanagedType.Bool)]\n"
        "  public static extern bool PostMessageW(IntPtr hWnd, uint message, "
        "IntPtr wParam, IntPtr lParam);\n"
        "}\n"
        "'@; "
        "$pids = @(Get-Process -Name 'fakenet-GUI' "
        "-ErrorAction SilentlyContinue | ForEach-Object { [int]$_.Id }); "
        "if ($pids.Count -eq 0) { Write-Output 'GUI_NOT_FOUND'; exit 3 }; "
        "$posted = [System.Collections.Generic.List[string]]::new(); "
        "$callback = [FakenetWindowClose+EnumWindowsProc] { "
        "param([IntPtr]$hWnd, [IntPtr]$lParam); "
        "[uint32]$ownerPid = 0; "
        "[void][FakenetWindowClose]::GetWindowThreadProcessId("
        "$hWnd, [ref]$ownerPid); "
        "if ($pids -contains [int]$ownerPid) { "
        "if ([FakenetWindowClose]::PostMessageW("
        "$hWnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)) { "
        "[void]$posted.Add(('{0}:{1}' -f $ownerPid, $hWnd)) } }; "
        "return $true }; "
        "[void][FakenetWindowClose]::EnumWindows("
        "$callback, [IntPtr]::Zero); "
        "if ($posted.Count -gt 0) { "
        "Write-Output ('CLOSE_REQUESTED count=' + $posted.Count); exit 0 }; "
        "Write-Output 'NO_TOP_LEVEL_WINDOW'; exit 4")
    try:
        completed = subprocess.run(
            ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
             '-ExecutionPolicy', 'Bypass', '-Command', script],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, '关闭请求异常: %s' % exc
    output = (completed.stdout or completed.stderr or '').strip()
    return (completed.returncode == 0 and
            'CLOSE_REQUESTED' in output), (output or
                                           '关闭请求 rc=%d' %
                                           completed.returncode)


def stop_gui_smoke(gui_proc, gui_mode):
    """Close the A9 GUI without force-killing a one-file child process."""
    if gui_mode != 'exe':
        gui_proc.terminate()
        gui_proc.wait(timeout=10)
        return True, '开发模式测试进程已结束'

    last_detail = ['关闭请求未执行']

    def request_when_window_exists():
        requested, detail = request_gui_close()
        last_detail[0] = detail
        return requested

    requested = wait_for(request_when_window_exists, 30, interval=0.25)
    detail = last_detail[0]
    if not requested:
        return False, detail
    closed = wait_for(
        lambda: 'fakenet-GUI.exe' not in active_fakenet_images(),
        10, interval=0.25)
    if closed:
        try:
            gui_proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    if not closed:
        return False, '%s;10 秒内仍有 fakenet-GUI.exe' % detail
    return True, '%s;进程已退出' % detail


def fnpr_session_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'Logs', 'fnpr-active-session.json')


def preflight_fnpr_sentinel():
    """Run the sole cross-host preflight before any WinDivert/DNS change."""
    import run_vm_diagnostics as diagnostic
    path = fnpr_session_path()
    log_root = os.path.dirname(path)
    os.makedirs(log_root, exist_ok=True)
    stamp = '%s-%d' % (time.strftime('%Y%m%d-%H%M%S'), os.getpid())
    refusal_dir = os.path.join(log_root, 'preflight-refused-' + stamp)
    os.makedirs(refusal_dir)
    network_before_path = os.path.join(
        refusal_dir, 'network-before.txt')
    network_after_path = os.path.join(
        refusal_dir, 'network-after.txt')
    network_before = diagnostic.capture_network_snapshot(
        network_before_path, 'preflight-refusal-before')
    transcript = []
    ok, nonce, transports = diagnostic.wait_for_sentinel(
        transcript_sink=transcript)
    payload = {
        'nonce': nonce,
        'sentinel_ipv4': diagnostic.SENTINEL_IPV4,
        'sentinel_port': diagnostic.SENTINEL_PORT,
        'preflight': transports,
        'ok': bool(ok),
        'created_epoch': time.time(),
    }
    diagnostic.write_json(path, payload)
    if ok:
        shutil.rmtree(refusal_dir, ignore_errors=True)
        return ok, nonce, transports, path

    network_after = diagnostic.capture_network_snapshot(
        network_after_path, 'preflight-refusal-after')
    network_unchanged = all(
        network_before.get(section) == network_after.get(section)
        for section in ('dns-client', 'route-ipv4'))
    core_not_started = not active_fakenet_images()
    transcript_path = os.path.join(
        refusal_dir, 'refusal-transcript.txt')
    evidence_path = os.path.join(
        refusal_dir, 'refusal-evidence.json')
    evidence = diagnostic.package_identity()
    evidence.update({
        'exit_code': EXIT_REFUSED,
        'nonce': nonce,
        'sentinel_ipv4': diagnostic.SENTINEL_IPV4,
        'sentinel_port': diagnostic.SENTINEL_PORT,
        'transports': transports,
        'network_unchanged': network_unchanged,
        'core_not_started': core_not_started,
        'network_before': network_before_path,
        'network_after': network_after_path,
        'transcript': transcript_path,
    })
    diagnostic.write_json(evidence_path, evidence)
    transcript.append('[EVIDENCE] %s' % evidence_path)
    with open(transcript_path, 'w', encoding='utf-8', newline='') as handle:
        handle.write('\n'.join(transcript) + '\n')
    print('[EVIDENCE] %s' % evidence_path, flush=True)
    return ok, nonce, transports, evidence_path


def collect_gui_logs(before, logs_root=None, target_dir=None):
    """Copy GUI logs new/changed since `before` into the evidence folder.

    The A9 GUI instance (and any GUI-launched core run) writes beside the
    exe; merging them here means one copy location for the whole evidence
    set. Copy failures are non-fatal (best effort).
    """
    logs = logs_root if logs_root is not None else gui_logs_root()
    if not logs or not os.path.isdir(logs):
        return []
    copied = []
    for name in os.listdir(logs):
        if not name.endswith('.log'):
            continue
        source = os.path.join(logs, name)
        try:
            if name in before and os.path.getmtime(source) <= before[name]:
                continue
        except OSError:
            continue
        os.makedirs(target_dir, exist_ok=True)
        try:
            import shutil
            shutil.copyfile(source, os.path.join(target_dir, name))
            copied.append(name)
        except OSError:
            pass
    return copied


def main():
    global LOG_DIR, FNPR_NONCE

    if os.name != 'nt':
        return refuse('仅支持 Windows')
    if not is_admin():
        return refuse('未提权:请通过 Run-Tests.cmd 启动(会自动请求提权,'
                      '此后全程免操作)')

    stamp = time.strftime('%Y%m%d-%H%M%S')
    LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'Logs', stamp)
    os.makedirs(LOG_DIR, exist_ok=True)
    global _GUI_LOGS_BEFORE
    _GUI_LOGS_BEFORE = snapshot_gui_logs()
    print('日志目录: %s' % LOG_DIR)

    # -- precondition: VM gate (fail-closed, three-state) -------------------
    vm = launcher.query_vm_state()
    if vm.verdict != launcher.VERDICT_VM:
        if vm.verdict == launcher.VERDICT_PHYSICAL:
            return refuse('本机识别为物理机(%s / %s)——GUI 验收必须在隔离 '
                          'VM 内运行(与 Start-*.ps1 同一约束)'
                          % (vm.manufacturer, vm.model))
        return refuse('VM 检测不确定(fail-closed):%s' % vm.detail)
    result('A1 VM 判定放行', 'PASS',
           'Win32_ComputerSystem 匹配 VM 特征(%s / %s)'
           % (vm.manufacturer, vm.model))

    existing_images = active_fakenet_images()
    if existing_images:
        return refuse('前置检查发现已有 %s；请回滚/重启隔离 VM，'
                      '本工具不会用强杀掩盖现场' %
                      ','.join(existing_images))
    preflight_ok, FNPR_NONCE, transports, session_path = \
        preflight_fnpr_sentinel()
    for transport in ('tcp', 'udp'):
        item = transports[transport]
        result('Sentinel 前置 %s' % transport.upper(),
               'PASS' if item['ok'] else 'FAIL',
               'nonce=%s;%s' % (FNPR_NONCE, item['detail']))
    if not preflight_ok:
        print('前置证据: %s' % session_path, flush=True)
        return EXIT_REFUSED
    print('[NEXT] Ubuntu 端无需再输入命令；请保持 Sentinel 窗口运行。',
          flush=True)

    # -- A2 physical-machine refusal (classifier-level inside a VM) ---------
    physical = launcher.parse_vm_state('Dell Inc.', 'OptiPlex 7090')
    physical2 = launcher.parse_vm_state('Acer', 'Predator PHN16-71')
    if (physical.verdict == launcher.VERDICT_PHYSICAL and
            physical2.verdict == launcher.VERDICT_PHYSICAL):
        result('A2 物理机拒绝分类', 'PASS',
               '分类器将真实物理机样本判为 physical(VM 内无法真机实测,'
               'GUI 侧拒绝由同一判定驱动)', '等效')
    else:
        result('A2 物理机拒绝分类', 'FAIL', '分类器结果异常', '等效')

    # -- A3 inconclusive state (live PATH-stripped subprocess) --------------
    probe = ('import sys; sys.path.insert(0, %r); '
             'from fakenet.gui import launcher as l; '
             'print(l.query_vm_state().verdict)' % REPO)
    try:
        env = {'SystemRoot': os.environ.get('SystemRoot', r'C:\Windows'),
               'WINDIR': os.environ.get('WINDIR', r'C:\Windows')}
        completed = subprocess.run(
            [sys.executable, '-c', probe], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=60, env=env)
        verdict = completed.stdout.strip()
    except Exception as exc:  # noqa: BLE001 - recorded as evidence
        verdict = 'error:%s' % exc
    if verdict == launcher.VERDICT_UNKNOWN:
        result('A3 不确定态 fail-closed', 'PASS',
               '剥离 PATH 的子进程中 powershell 不可达 → query_vm_state '
               '返回 unknown(启动门将拒绝)', '实测')
    else:
        result('A3 不确定态 fail-closed', 'FAIL',
               '预期 unknown,实际 %r' % verdict, '实测')

    # -- A4 UAC return-value interpretation (deterministic branch) ----------
    ok_cancel = launcher.interpret_shell_result(launcher.SE_ERR_ACCESSDENIED)
    ok_success = launcher.interpret_shell_result(33)
    if not ok_cancel[0] and ok_success[0]:
        result('A4 UAC 取消/失败分支', 'PASS',
               'SE_ERR_ACCESSDENIED(5) 判为"已取消 UAC 未启动",>32 判为已'
               '启动(真实点击 No 无法免交互自动化,本项为等效分支覆盖)',
               '等效')
    else:
        result('A4 UAC 取消/失败分支', 'FAIL', '返回值解释异常', '等效')

    # -- A5 config writer + validator agreement ------------------------------
    config_path = os.path.join(LOG_DIR, 'smoke_config.ini')
    model, errors = build_smoke_config(config_path)
    if errors:
        result('A5 配置写入与校验一致', 'FAIL',
               '最小冒烟配置存在 %d 个校验错误: %s'
               % (len(errors), errors[0].message))
    else:
        result('A5 配置写入与校验一致', 'PASS',
               'GUI 写出最小配置(DivertTraffic=No,单 RawTCPListener)校验 '
               '0 错误: %s' % config_path)

    # -- A6/A7/A8 need a real fakenet.exe (image-name based lifecycle and
    #    duplicate-gate assertions).  The dev fallback cannot be asserted
    #    reliably (python.exe has no distinct image name), so SKIP rather
    #    than flake: put fakenet.exe next to this script / repo root / dist.
    fakenet_exe = find_file('fakenet.exe')
    fakenet_log = os.path.join(LOG_DIR, 'fakenet.log')
    stop_flag = os.path.join(LOG_DIR, 'stop.flag')
    if not fakenet_exe:
        for name in ('A6 提权启动', 'A7 双实例门', 'A8 停止旗标优雅停止'):
            result(name, 'SKIP',
                   '需要 fakenet.exe(放在脚本同目录/仓库根/dist 下重跑)',
                   '实测')
    else:
        params = '-c "%s" -l "%s" -f "%s" -p -v' % (config_path, fakenet_log,
                                                    stop_flag)
        ok, detail = launcher.launch_elevated(
            fakenet_exe, params, os.path.dirname(config_path))
        if not ok:
            result('A6 提权启动', 'FAIL', 'ShellExecute 结果: %s' % detail)
            return finish()
        appeared = wait_for(launcher.is_fakenet_running, 40)
        log_ready = wait_for(lambda: os.path.isfile(fakenet_log) and
                             os.path.getsize(fakenet_log) > 0, 20)
        wait_for(lambda: startup_log_decided(fakenet_log), 40)
        start_ok, start_detail = evaluate_start_log(
            read_core_log(fakenet_log))
        running = launcher.is_fakenet_running()
        a6_ok = appeared and log_ready and start_ok and running
        if a6_ok:
            result('A6 提权启动', 'PASS',
                   'fakenet.exe 稳定运行;日志已记录成功启动: %s'
                   % fakenet_exe)
        else:
            failures = []
            if not appeared:
                failures.append('40 秒内未见 fakenet.exe 存活')
            if not log_ready:
                failures.append('核心日志未就绪')
            if not start_ok:
                failures.append(start_detail)
            if not running:
                failures.append('证据判定时 fakenet.exe 已退出')
            result('A6 提权启动', 'FAIL', ';'.join(failures))

        if a6_ok and launcher.is_fakenet_running():
            result('A7 双实例门', 'PASS',
                   '真实 fakenet.exe 运行中被 is_fakenet_running 检出'
                   '(GUI 启动门将拒绝二次启动)')
            a7_ok = True
        else:
            a7_ok = False
            result('A7 双实例门', 'FAIL',
                   'A6 未证明稳定启动或实例已提前退出')

        if a6_ok and a7_ok:
            with open(stop_flag, 'w') as handle:
                handle.write('stop\n')
            stopped = wait_for(
                lambda: not launcher.is_fakenet_running(), 40)
            wait_for(
                lambda: 'FakeNet-NG exiting: rc=' in
                read_core_log(fakenet_log),
                10)
            stop_ok, stop_detail = evaluate_stop_log(
                read_core_log(fakenet_log))
            if stopped and stop_ok:
                result('A8 停止旗标优雅停止', 'PASS',
                       '%s;-l 日志: %s' % (stop_detail, fakenet_log))
            else:
                details = []
                if not stopped:
                    details.append('40 秒内未退出')
                if not stop_ok:
                    details.append(stop_detail)
                result('A8 停止旗标优雅停止', 'FAIL',
                       ';'.join(details))
        else:
            result('A8 停止旗标优雅停止', 'FAIL',
                   'A6/A7 前置证据未通过,不得判定优雅停止')

        if launcher.is_fakenet_running():
            if not os.path.exists(stop_flag):
                with open(stop_flag, 'w') as handle:
                    handle.write('stop\n')
                wait_for(
                    lambda: not launcher.is_fakenet_running(), 10)
        if launcher.is_fakenet_running():
            result('A8 停止后无残留', 'FAIL',
                   'fakenet.exe 仍在运行；不执行 taskkill，请导出证据并回滚快照')

    # -- A9 GUI launch smoke ----------------------------------------------------
    gui_exe = find_file('fakenet-GUI.exe')
    if gui_exe:
        gui_cmd = [gui_exe]
        gui_mode = 'exe'
    else:
        gui_cmd = [sys.executable, '-m', 'fakenet.gui.main']
        gui_mode = 'dev(python -m fakenet.gui.main)'
    try:
        gui_proc = subprocess.Popen(
            gui_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            if gui_mode == 'dev' else 0)
        time.sleep(6)
        alive = gui_proc.poll() is None
        closed, close_detail = stop_gui_smoke(gui_proc, gui_mode)
    except Exception as exc:  # noqa: BLE001 - recorded as evidence
        alive = False
        result('A9 GUI 启动冒烟', 'FAIL', '异常: %s' % exc)
    else:
        result('A9 GUI 启动冒烟', 'PASS' if alive and closed else 'FAIL',
               '模式 %s;%s;%s' % (
                   gui_mode,
                   '6 秒后仍存活(无崩溃)' if alive else '启动后即退出',
                   close_detail))
    # -- A10 process flow attribution (v1.32 12.32.2) -------------------------
    run_a10_process_flow(fakenet_exe)

    # -- A11 takeover sink connectivity (plan 2026.08.21-01 §5.2) -------------
    run_a11_sink_reply(fakenet_exe)

    return finish()


def run_a10_process_flow(fakenet_exe):
    """Egress-policy run: our own direct TCP connect must be attributed.

    The runner process itself is the "sample": its outbound SYN to an
    unreviewed global IPv4 is DIVERT_FAKE'd and must appear as a
    PROCESS_FLOW event carrying this interpreter's pid and image name.
    """
    if not fakenet_exe:
        result('A10 进程归因', 'SKIP',
               '需要 fakenet.exe(放在脚本同目录/仓库根/dist 下重跑)', '实测')
        return
    import run_policy_feature_tests as policy
    config_path = os.path.join(LOG_DIR, 'a10_config.ini')
    model, errors = policy.build_policy_config(
        config_path, 'api.deepseek.com, *.deepseek.com',
        takeover_ip=policy.TAKEOVER_SINK)
    if errors:
        result('A10 进程归因', 'FAIL', '配置错误: %s' % errors[0].message)
        return
    core_log = os.path.join(LOG_DIR, 'a10_fakenet.log')
    stop_flag = os.path.join(LOG_DIR, 'a10_stop.flag')
    params = '-c "%s" -l "%s" -f "%s" -p -v' % (config_path, core_log,
                                                stop_flag)
    ok, detail = launcher.launch_elevated(
        fakenet_exe, params, os.path.dirname(config_path))
    if not ok:
        result('A10 进程归因', 'FAIL', 'ShellExecute 结果: %s' % detail)
        return
    wait_for(launcher.is_fakenet_running, 40)
    ready = wait_for(
        lambda: 'DOMAIN_TAKEOVER_READY' in
        (read_core_log(core_log) if os.path.isfile(core_log) else ''),
        60)
    if not ready:
        result('A10 进程归因', 'FAIL', '60 秒内未见 DOMAIN_TAKEOVER_READY')
    else:
        connected, _received = policy.probe_direct_ipv4(
            policy.UNREVIEWED_IPV4, policy.UNREVIEWED_PORT)
        expected_pid = str(os.getpid())
        expected_image = os.path.basename(sys.executable).replace(' ', '_')
        flow_line = wait_for(lambda: any(
            line.strip().endswith('pid=%s' % expected_pid) or
            (' pid=%s ' % expected_pid) in line
            for line in (read_core_log(core_log) if
                         os.path.isfile(core_log) else '').splitlines()
            if 'PROCESS_FLOW' in line), 30)
        log_text = read_core_log(core_log)
        attributed = ('PROCESS_FLOW' in log_text and
                      'pid=%s' % expected_pid in log_text and
                      expected_image.lower() in log_text.lower())
        diverted = policy.divert_fake_logged(
            log_text, policy.UNREVIEWED_IPV4)
        result('A10 进程归因', 'PASS'
               if connected and flow_line and attributed and diverted
               else 'FAIL',
               '直连 %s:%s 连接=%s;PROCESS_FLOW 含本进程 pid=%s/%s=%s;'
               'DIVERT_FAKE=%s' % (
                   policy.UNREVIEWED_IPV4, policy.UNREVIEWED_PORT,
                   connected, expected_pid, expected_image,
                   attributed, diverted))
    if os.path.exists(stop_flag) or launcher.is_fakenet_running():
        if not os.path.exists(stop_flag):
            with open(stop_flag, 'w') as handle:
                handle.write('stop\n')
        wait_for(lambda: not launcher.is_fakenet_running(), 40)


def run_a11_sink_reply(fakenet_exe):
    """A11 proves same-nonce TCP+UDP delivery reaches Ubuntu, not localhost."""
    if not fakenet_exe:
        result('A11 接管 sink 连通', 'SKIP',
               '需要 fakenet.exe(放在脚本同目录/仓库根/dist 下重跑)', '实测')
        return
    import run_policy_feature_tests as policy
    config_path = os.path.join(LOG_DIR, 'a11_config.ini')
    model, errors = policy.build_policy_config(
        config_path, 'api.deepseek.com, *.deepseek.com',
        takeover_ip=policy.TAKEOVER_SINK)
    if errors:
        result('A11 接管 sink 连通', 'FAIL', '配置错误: %s' % errors[0].message)
        return
    work_dir = os.path.dirname(config_path)
    core_log = os.path.join(LOG_DIR, 'a11_fakenet.log')
    stop_flag = os.path.join(LOG_DIR, 'a11_stop.flag')
    params = '-c "%s" -l "%s" -f "%s" -p -v' % (config_path, core_log,
                                                stop_flag)
    ok, detail = launcher.launch_elevated(fakenet_exe, params, work_dir)
    if not ok:
        result('A11 接管 sink 连通', 'FAIL', 'ShellExecute 结果: %s' % detail)
        return
    wait_for(launcher.is_fakenet_running, 40)
    ready = wait_for(
        lambda: 'DOMAIN_TAKEOVER_READY' in
        (read_core_log(core_log) if os.path.isfile(core_log) else ''),
        60)
    if not ready:
        result('A11 接管 sink 连通', 'FAIL', '60 秒内未见 DOMAIN_TAKEOVER_READY')
    else:
        sink = policy.TAKEOVER_SINK
        probe_domain = 'login.example.com'
        addresses = policy.nslookup_addresses(probe_domain)
        answered = policy.answers_only_sink(addresses, sink)

        import run_vm_diagnostics as diagnostic
        target_ok, target = diagnostic.probe_fnpr_transports(
            FNPR_NONCE, 'target', timeout=5.0)
        wait_for(lambda: 'ALLOW_TAKEOVER_SINK' in read_core_log(core_log), 10)
        log_text = read_core_log(core_log)
        allowed = ('ALLOW_TAKEOVER_SINK' in log_text and
                   'ip=%s' % sink in log_text)
        local_divert = ('DIVERT_FAKE' in log_text and
                        'original_ip=%s' % sink in log_text)

        report_ok = False
        import glob as _glob
        for report in sorted(
                _glob.glob(os.path.join(work_dir, 'report_*.html')),
                key=os.path.getmtime, reverse=True):
            try:
                with open(report, 'r', encoding='utf-8',
                          errors='replace') as handle:
                    if 'python.exe' in handle.read():
                        report_ok = True
                        break
            except OSError:
                continue

        result('A11 接管 sink 连通', 'PASS'
               if answered and target_ok and allowed and not local_divert
               else 'FAIL',
               'DNS 应答=%s;nonce=%s;TCP=%s;UDP=%s;Ubuntu裁决=%s;'
               '本地DIVERT_FAKE=%s' % (
                   answered, FNPR_NONCE, target['tcp']['ok'],
                   target['udp']['ok'], allowed, local_divert))
    if os.path.exists(stop_flag) or launcher.is_fakenet_running():
        if not os.path.exists(stop_flag):
            with open(stop_flag, 'w') as handle:
                handle.write('stop\n')
        wait_for(lambda: not launcher.is_fakenet_running(), 40)


def finish():
    failed = [r for r in RESULTS if r[0] == 'FAIL']
    leftovers = active_fakenet_images()
    if leftovers:
        result('结束后进程残留', 'FAIL',
               '%s；未强杀，请导出证据并回滚快照' % ','.join(leftovers))
        failed = [r for r in RESULTS if r[0] == 'FAIL']
    if LOG_DIR is not None:
        copied = collect_gui_logs(_GUI_LOGS_BEFORE, target_dir=os.path.join(
            LOG_DIR, 'gui-logs'))
        if copied:
            print('GUI 日志已并入: %s (共 %d 个: %s)' % (
                os.path.join(LOG_DIR, 'gui-logs'), len(copied),
                ', '.join(sorted(copied))))
    print('\n===== 汇总: %d 项,失败 %d 项 =====' % (len(RESULTS), len(failed)))
    for status, name, detail, level in RESULTS:
        print('  %-6s %-24s %s' % (status, name, detail))
    print('明细: %s' % os.path.join(LOG_DIR, 'results.tsv'))
    return EXIT_FAIL if failed else EXIT_PASS


if __name__ == '__main__':
    sys.exit(main())
