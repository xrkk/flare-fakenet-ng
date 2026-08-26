# -*- coding: utf-8 -*-
"""One-click, human-in-the-loop VM diagnostic evidence collector.

The runner never changes adapter, route, firewall, or DNS state itself.  It
preflights the Ubuntu FNPR/1 endpoint, launches the diagnostic GUI, creates a
bounded TEST-NET TCP connection after the core is ready, observes the stop
request, and invokes Export-Logs.ps1.  A hung core is deliberately not killed:
its unfinished stop boundary is the evidence this runner exists to collect.
"""

import datetime
import glob
import os
import socket
import subprocess
import sys
import time
import uuid


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from fakenet.gui import launcher  # noqa: E402


EXIT_CAPTURED = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2
SENTINEL_IPV4 = '192.168.204.1'
SENTINEL_PORT = 443
SENTINEL_WAIT_SECONDS = 120
SENTINEL_RETRY_SECONDS = 10
SESSION_WAIT_SECONDS = 20 * 60
STOP_OBSERVE_SECONDS = 45
TEST_TCP_IPV4 = '198.51.100.10'
TEST_TCP_PORT = 80


def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:  # noqa: BLE001 - fail closed outside Windows
        return False


def _read_bounded_line(sock, limit=512):
    data = bytearray()
    while len(data) < limit:
        chunk = sock.recv(min(128, limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b'\n' in chunk:
            break
    return bytes(data)


def probe_sentinel_once(nonce, timeout=3.0, tcp_connect=None,
                        udp_socket_factory=None):
    """Return ``(ok, detail)`` after same-nonce TCP and UDP FNPR/1 probes."""
    request = ('FNPR/1|%s|preflight\n' % nonce).encode('ascii')
    expected = ('FNPR/1|%s|OK\n' % nonce).encode('ascii')
    tcp_connect = tcp_connect or socket.create_connection
    udp_socket_factory = udp_socket_factory or (
        lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    try:
        tcp = tcp_connect((SENTINEL_IPV4, SENTINEL_PORT), timeout)
        try:
            tcp.settimeout(timeout)
            tcp.sendall(request)
            tcp_response = _read_bounded_line(tcp)
        finally:
            tcp.close()
        if tcp_response != expected:
            return False, 'TCP nonce 响应不匹配'
    except OSError as exc:
        return False, 'TCP 不可达: %s' % exc

    try:
        udp = udp_socket_factory()
        try:
            udp.settimeout(timeout)
            udp.sendto(request, (SENTINEL_IPV4, SENTINEL_PORT))
            udp_response, peer = udp.recvfrom(512)
        finally:
            udp.close()
        if peer[0] != SENTINEL_IPV4 or udp_response != expected:
            return False, 'UDP nonce 响应不匹配'
    except OSError as exc:
        return False, 'UDP 不可达: %s' % exc
    return True, 'TCP/UDP 同 nonce 前置通过'


def wait_for_sentinel():
    nonce = 'diag-%s' % uuid.uuid4().hex
    ok, detail = probe_sentinel_once(nonce)
    if ok:
        print('[PASS] Ubuntu Sentinel: %s' % detail, flush=True)
        return True, nonce

    print('', flush=True)
    print('[ACTION REQUIRED 1/1]', flush=True)
    print('在 Ubuntu 运行仓库根目录的 Start-FNPR-Sentinel.sh，'
          '并保持窗口打开。', flush=True)
    print('Windows 端正在等待 %s:%s 的 TCP+UDP，同一窗口无需输入其他命令。'
          % (SENTINEL_IPV4, SENTINEL_PORT), flush=True)
    deadline = time.monotonic() + SENTINEL_WAIT_SECONDS
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        remaining = max(0, int(deadline - time.monotonic()))
        print('[WAIT] Ubuntu Sentinel 尚未就绪，剩余约 %d 秒；上次结果: %s'
              % (remaining, detail), flush=True)
        time.sleep(min(SENTINEL_RETRY_SECONDS,
                       max(0, deadline - time.monotonic())))
        ok, detail = probe_sentinel_once(nonce)
        if ok:
            print('[PASS] Ubuntu Sentinel: %s; nonce=%s' % (detail, nonce),
                  flush=True)
            return True, nonce
    print('[REFUSED] Ubuntu Sentinel 前置失败: %s' % detail, flush=True)
    print('未启动 GUI，未修改 Windows 网络。', flush=True)
    return False, nonce


def snapshot_logs(log_root):
    snapshot = {}
    for path in glob.glob(os.path.join(log_root, '*.log')):
        try:
            stat = os.stat(path)
            snapshot[os.path.abspath(path)] = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            pass
    return snapshot


def changed_core_logs(log_root, before):
    changed = []
    for path in glob.glob(os.path.join(log_root, 'fakenet-*.log')):
        if os.path.basename(path).lower().startswith('fakenet-gui-'):
            continue
        try:
            stat = os.stat(path)
        except OSError:
            continue
        identity = (stat.st_mtime_ns, stat.st_size)
        if before.get(os.path.abspath(path)) != identity:
            changed.append((stat.st_mtime_ns, os.path.abspath(path)))
    return [path for unused, path in sorted(changed, reverse=True)]


def read_text(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as handle:
            return handle.read()
    except OSError:
        return ''


def evaluate_core_log(content):
    """Return ``(state, detail)`` for the exact diagnostic decision."""
    takeover = 'DOMAIN_TAKEOVER_READY' in content
    ordinary = 'EGRESS_CONTROL_READY' in content and not takeover
    stop_requested = 'Stop flag found at ' in content
    stop_complete = (
        'STOP_PHASE_END phase=complete' in content and
        'FakeNet-NG exiting: rc=0' in content)
    if stop_complete and takeover:
        return 'complete', '接管已启用，停止完整结束'
    if stop_complete and ordinary:
        return 'config-missing', '停止完整结束，但核心未进入 takeover'
    if stop_requested:
        return 'observing-stop', '停止请求已进入核心'
    if takeover:
        return 'takeover-ready', '核心已进入 takeover'
    if ordinary:
        return 'ordinary-ready', '核心仅进入普通出站策略'
    return 'waiting', '等待核心启动证据'


def open_bounded_test_connection():
    """Create one safe TEST-NET connection and retain it through stop."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(8)
    try:
        sock.connect((TEST_TCP_IPV4, TEST_TCP_PORT))
        sock.sendall(b'GET /diagnostic HTTP/1.1\r\nHost: diagnostic.invalid\r\n')
        return sock, 'TEST-NET TCP 连接已建立并保留'
    except OSError as exc:
        sock.close()
        return None, 'TEST-NET TCP 探针未建立: %s' % exc


def run_export(started_utc):
    exporter = os.path.join(SCRIPT_DIR, 'Export-Logs.ps1')
    command = [
        'powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
        '-ExecutionPolicy', 'Bypass', '-File', exporter,
        '-SinceUtc', started_utc,
        '-SessionLabel', 'diagnostic',
    ]
    completed = subprocess.run(command, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True,
                               errors='replace', timeout=120)
    print(completed.stdout, end='' if completed.stdout.endswith('\n') else '\n',
          flush=True)
    if completed.returncode != 0:
        return False, '证据导出失败，退出码 %d' % completed.returncode
    for line in completed.stdout.splitlines():
        if line.startswith('EVIDENCE_PATH='):
            return True, line.split('=', 1)[1]
    return False, '导出器未返回 EVIDENCE_PATH'


def main():
    if os.name != 'nt':
        print('[REFUSED] 诊断入口只允许在隔离 Windows VM 运行。')
        return EXIT_REFUSED
    if not is_admin():
        print('[REFUSED] 请双击 Run-Diagnostics.cmd；它会自动请求一次 UAC。')
        return EXIT_REFUSED
    vm = launcher.query_vm_state()
    if vm.verdict != launcher.VERDICT_VM:
        print('[REFUSED] VM 判定未通过: %s' % vm.detail)
        return EXIT_REFUSED
    if launcher.is_fakenet_running():
        print('[REFUSED] 已有 fakenet.exe 运行。请回滚/重启 VM 后再诊断；'
              '本工具不会强杀并掩盖恢复状态。')
        return EXIT_REFUSED

    gui_exe = os.path.join(REPO, 'fakenet-GUI.exe')
    if not os.path.isfile(gui_exe):
        print('[REFUSED] 诊断包根目录缺少 fakenet-GUI.exe: %s' % gui_exe)
        return EXIT_REFUSED
    ok, nonce = wait_for_sentinel()
    if not ok:
        return EXIT_REFUSED

    log_root = os.path.join(REPO, 'Logs')
    os.makedirs(log_root, exist_ok=True)
    before = snapshot_logs(log_root)
    started = datetime.datetime.now(datetime.timezone.utc)
    started_utc = started.isoformat().replace('+00:00', 'Z')

    print('', flush=True)
    print('[GUI DIAGNOSTIC]', flush=True)
    print('GUI 即将打开。请只在 GUI 中完成以下操作，无需输入 Windows 命令:',
          flush=True)
    print('  1. 启用“将其他域名导向私网分析主机”，确认地址为 '
          '192.168.204.1。', flush=True)
    print('  2. 保存到一个非默认 INI，然后点击“启动 FakeNet-NG”。',
          flush=True)
    print('  3. 等待本控制台显示“现在点击停止”后，点击 GUI 的“停止”。',
          flush=True)
    print('之后本工具会自动等待 45 秒并导出证据。不要使用任务管理器强杀。',
          flush=True)
    gui_process = subprocess.Popen([gui_exe], cwd=REPO)
    print('[WAIT] GUI 已打开；等待本次核心日志。sentinel nonce=%s' % nonce,
          flush=True)

    active_socket = None
    probe_attempted = False
    core_path = None
    stop_seen_at = None
    last_state = None
    outcome = 'timeout'
    deadline = time.monotonic() + SESSION_WAIT_SECONDS
    try:
        while time.monotonic() < deadline:
            candidates = changed_core_logs(log_root, before)
            if candidates:
                core_path = candidates[0]
                content = read_text(core_path)
                state, detail = evaluate_core_log(content)
                if state != last_state:
                    print('[STATE] %s: %s' % (state, detail), flush=True)
                    last_state = state
                if state in ('takeover-ready', 'ordinary-ready') and \
                        not probe_attempted:
                    probe_attempted = True
                    active_socket, probe_detail = open_bounded_test_connection()
                    print('[PROBE] %s' % probe_detail, flush=True)
                    print('[ACTION REQUIRED] 现在点击 GUI 的“停止”按钮。',
                          flush=True)
                if state == 'complete':
                    outcome = 'complete'
                    break
                if state == 'config-missing':
                    outcome = 'config-missing'
                    break
                if state == 'observing-stop' and stop_seen_at is None:
                    stop_seen_at = time.monotonic()
                    print('[WAIT] 停止请求已进入核心；观察 45 秒，随后自动导出。',
                          flush=True)
                if stop_seen_at is not None and \
                        time.monotonic() - stop_seen_at >= STOP_OBSERVE_SECONDS:
                    outcome = 'stop-incomplete'
                    break
            if gui_process.poll() is not None and core_path is None:
                outcome = 'gui-exited-before-core'
                break
            time.sleep(1)
    finally:
        if active_socket is not None:
            try:
                active_socket.close()
            except OSError:
                pass

    exported, export_detail = run_export(started_utc)
    if exported:
        print('[EVIDENCE] %s' % export_detail, flush=True)
    else:
        print('[FAIL] %s' % export_detail, flush=True)
        return EXIT_FAILED

    if outcome == 'complete':
        print('[CAPTURED] 本次 takeover 和完整停止均有可观察证据。', flush=True)
    elif outcome == 'config-missing':
        print('[CAPTURED] 已捕获 GUI 会话未进入 takeover；请回传证据目录。',
              flush=True)
    elif outcome == 'stop-incomplete':
        print('[CAPTURED] 已捕获停止未在 45 秒内完成；不要强杀后继续验收。',
              flush=True)
        print('请回传证据目录，然后回滚隔离 VM 快照。', flush=True)
    else:
        print('[CAPTURED] 诊断流程未完成: %s；请回传证据目录。' % outcome,
              flush=True)
    print('现在可以关闭 GUI，并在 Ubuntu Sentinel 窗口按 Ctrl+C。', flush=True)
    return EXIT_CAPTURED


if __name__ == '__main__':
    sys.exit(main())
