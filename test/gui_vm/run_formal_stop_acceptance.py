# -*- coding: utf-8 -*-
"""Formal v34 three-round GUI stop acceptance (IMP-005 / ACC-003)."""

import datetime
import glob
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid


HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
for path in (REPO, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

from fakenet.gui import launcher  # noqa: E402
import run_gui_vm_acceptance as acceptance  # noqa: E402
import run_vm_diagnostics as diagnostic  # noqa: E402


EXIT_PASS, EXIT_FAIL, EXIT_REFUSED = 0, 1, 2
ROUND_COUNT = 3
READY_TIMEOUT_SECONDS = 10 * 60
STOP_TIMEOUT_SECONDS = 10


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        '+00:00', 'Z')


def read_text(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as handle:
            return handle.read()
    except OSError:
        return ''


def snapshot_logs():
    root = os.path.join(REPO, 'Logs')
    result = {}
    for path in glob.glob(os.path.join(root, '*.log')):
        try:
            result[path] = os.path.getmtime(path)
        except OSError:
            pass
    return result


def changed_logs(before, gui=False):
    root = os.path.join(REPO, 'Logs')
    paths = []
    for path in glob.glob(os.path.join(root, '*.log')):
        name = os.path.basename(path).lower()
        is_gui = 'fakenet-gui-' in name
        if is_gui != gui:
            continue
        try:
            if path not in before or os.path.getmtime(path) > before[path]:
                paths.append(path)
        except OSError:
            continue
    return sorted(paths, key=os.path.getmtime, reverse=True)


def stop_boundaries_closed(content):
    active = set()
    for line in content.splitlines():
        if 'STOP_PHASE_BEGIN phase=' in line:
            active.add(('phase', line.split('phase=', 1)[1].split()[0]))
        elif 'STOP_PHASE_END phase=' in line:
            active.discard(('phase', line.split('phase=', 1)[1].split()[0]))
        elif 'STOP_PROVIDER_BEGIN name=' in line:
            active.add(('provider', line.split('name=', 1)[1].split()[0]))
        elif 'STOP_PROVIDER_END name=' in line:
            active.discard(('provider', line.split('name=', 1)[1].split()[0]))
    return not active, sorted('%s:%s' % item for item in active)


def _new_mei_dirs():
    return set(glob.glob(os.path.join(tempfile.gettempdir(), '_MEI*')))


def cleanup_round_gui(gui, mei_before):
    """Close the real one-file GUI image, then verify its _MEI is gone."""
    gui_ok, gui_detail = acceptance.stop_gui_smoke(gui, 'exe')
    remaining = []

    def mei_cleaned():
        remaining[:] = sorted(_new_mei_dirs() - mei_before)
        return not remaining

    mei_ok = acceptance.wait_for(mei_cleaned, 10, interval=0.25)
    return gui_ok, gui_detail, mei_ok, remaining


def run_round(round_number, evidence_dir):
    rows = []
    timeline = []
    core_path = None
    gui_log = None
    nonce = None

    def persist():
        with open(os.path.join(evidence_dir, 'round-%d.json' % round_number),
                  'w', encoding='utf-8') as handle:
            json.dump({'round': round_number, 'nonce': nonce,
                       'core_log': core_path, 'gui_log': gui_log,
                       'results': rows, 'timeline': timeline}, handle,
                      ensure_ascii=False, indent=2, sort_keys=True)
            handle.write('\n')
        return rows, timeline

    def event(name, detail):
        timeline.append({'event': name, 'utc': utc_now(), 'detail': detail})

    def check(name, ok, detail):
        rows.append({'check': name, 'status': 'PASS' if ok else 'FAIL',
                     'detail': detail})
        print('[%s] R%d %s: %s' % (
            'PASS' if ok else 'FAIL', round_number, name, detail), flush=True)
        return ok

    if acceptance.active_fakenet_images():
        check('clean_start', False, '存在 fakenet 进程；不强杀')
        return persist()

    nonce = 'v34-r%d-%s' % (round_number, uuid.uuid4().hex)
    preflight_ok, preflight = diagnostic.probe_fnpr_transports(
        nonce, 'preflight')
    for transport in ('tcp', 'udp'):
        item = preflight[transport]
        check('sentinel_preflight_%s' % transport, item['ok'],
              'nonce=%s;%s' % (nonce, item['detail']))
    if not preflight_ok:
        return persist()

    before = snapshot_logs()
    mei_before = _new_mei_dirs()
    gui_exe = os.path.join(REPO, 'fakenet-GUI.exe')
    gui = subprocess.Popen([gui_exe], cwd=REPO)
    event('gui_started', 'pid=%d nonce=%s' % (gui.pid, nonce))
    print('\n[ROUND %d/3]' % round_number, flush=True)
    print('在 GUI 中载入/确认 takeover 配置并点击“启动 FakeNet-NG”。',
          flush=True)
    print('[WAIT] 等待 DOMAIN_TAKEOVER_READY；不要输入 Windows 命令。',
          flush=True)

    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        candidates = changed_logs(before, gui=False)
        if candidates:
            candidate = candidates[0]
            content = read_text(candidate)
            if 'DOMAIN_TAKEOVER_READY' in content:
                core_path = candidate
                break
            if any(marker in content for marker in acceptance.CORE_FAILURE_MARKERS):
                core_path = candidate
                break
        if gui.poll() is not None:
            break
        time.sleep(1)

    if not core_path or 'DOMAIN_TAKEOVER_READY' not in read_text(core_path):
        check('takeover_ready', False,
              '十分钟内未进入 DOMAIN_TAKEOVER_READY')
        return persist()
    check('takeover_ready', True, core_path)

    target_ok, target = diagnostic.probe_fnpr_transports(
        nonce, 'target', timeout=5.0)
    for transport in ('tcp', 'udp'):
        item = target[transport]
        check('target_%s' % transport, item['ok'],
              'nonce=%s;%s' % (nonce, item['detail']))
    time.sleep(0.5)
    core_content = read_text(core_path)
    check('sink_verdict',
          target_ok and 'ALLOW_TAKEOVER_SINK' in core_content,
          'TCP/UDP target 与核心裁决必须同时存在')

    active_socket, socket_detail = diagnostic.open_bounded_test_connection()
    check('incomplete_http_connection', active_socket is not None,
          socket_detail)
    if active_socket is None:
        return persist()

    stop_flag = core_path + '.stopflag'
    print('[ACTION REQUIRED] 现在点击 GUI 的“停止 FakeNet-NG”按钮。',
          flush=True)
    print('[WAIT] 本工具自动计时；不要 taskkill，不要关闭控制台。',
          flush=True)
    event('stop_prompt', stop_flag)
    stop_seen = None
    feedback_seen = None
    handle_returned = None
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        now = time.monotonic()
        if stop_seen is None and os.path.isfile(stop_flag):
            stop_seen = now
            event('stop_flag_seen', stop_flag)
        gui_candidates = changed_logs(before, gui=True)
        if gui_candidates:
            gui_log = gui_candidates[0]
            gui_text = read_text(gui_log)
            if stop_seen is not None and feedback_seen is None and \
                    'Stop requested via flag:' in gui_text:
                feedback_seen = now
                event('gui_feedback_seen', gui_log)
            if stop_seen is not None and handle_returned is None and \
                    'FakeNet session exited: code=0' in gui_text:
                handle_returned = now
                event('top_handle_returned', gui_log)
        if handle_returned is not None:
            break
        time.sleep(0.05)

    try:
        active_socket.close()
    except OSError:
        pass
    feedback_seconds = (feedback_seen - stop_seen
                        if feedback_seen is not None and stop_seen is not None
                        else None)
    exit_seconds = (handle_returned - stop_seen
                    if handle_returned is not None and stop_seen is not None
                    else None)
    check('feedback_within_1s',
          feedback_seconds is not None and feedback_seconds <= 1.0,
          'seconds=%s' % ('missing' if feedback_seconds is None else
                          '%.3f' % feedback_seconds))
    check('top_handle_within_5s',
          exit_seconds is not None and exit_seconds <= 5.0,
          'seconds=%s' % ('missing' if exit_seconds is None else
                          '%.3f' % exit_seconds))

    core_content = read_text(core_path)
    stop_ok, stop_detail = acceptance.evaluate_stop_log(core_content)
    boundaries_ok, active = stop_boundaries_closed(core_content)
    check('core_rc0', stop_ok, stop_detail)
    check('providers_closed', boundaries_ok,
          'unclosed=%s' % (','.join(active) if active else '-'))
    check('no_fakenet_residual', not launcher.is_fakenet_running(),
          '按进程镜像名只读检查')
    gui_ok, gui_detail, mei_ok, remaining_mei = cleanup_round_gui(
        gui, mei_before)
    check('gui_closed_normally', gui_ok, gui_detail)
    check('no_new_onefile_mei', mei_ok,
          'new=%s' % remaining_mei)

    return persist()


def main():
    if os.name != 'nt' or not acceptance.is_admin():
        print('[REFUSED] 三轮停止验收只允许从已提权 Run-Tests.cmd 运行。')
        return EXIT_REFUSED
    vm = launcher.query_vm_state()
    if vm.verdict != launcher.VERDICT_VM:
        print('[REFUSED] VM 判定未通过: %s' % vm.detail)
        return EXIT_REFUSED
    manifest = diagnostic.package_identity()
    if manifest.get('core_bundle_mode') != 'pyinstaller-onedir':
        print('[REFUSED] manifest 不是 pyinstaller-onedir: %r' % manifest)
        return EXIT_REFUSED
    if not os.path.isfile(os.path.join(REPO, 'fakenet.exe')) or \
            not os.path.isdir(os.path.join(REPO, '_internal')):
        print('[REFUSED] 包根缺少 fakenet.exe 或 _internal。')
        return EXIT_REFUSED

    stamp = time.strftime('%Y%m%d-%H%M%S')
    evidence_dir = os.path.join(HERE, 'Logs', 'formal-stop-' + stamp)
    os.makedirs(evidence_dir)
    network_before_path = os.path.join(evidence_dir, 'network-before.txt')
    network_after_path = os.path.join(evidence_dir, 'network-after.txt')
    network_before = diagnostic.capture_network_snapshot(
        network_before_path, 'formal-stop-before')
    all_rows = []
    for round_number in range(1, ROUND_COUNT + 1):
        rows, unused_timeline = run_round(round_number, evidence_dir)
        all_rows.extend(rows)
        if any(row['status'] == 'FAIL' for row in rows):
            break
    network_after = diagnostic.capture_network_snapshot(
        network_after_path, 'formal-stop-after')
    for name, section in (('dns_restored', 'dns-client'),
                          ('route_restored', 'route-ipv4')):
        ok = network_before.get(section) == network_after.get(section)
        all_rows.append({'check': name, 'status': 'PASS' if ok else 'FAIL',
                         'detail': 'exact before/after comparison'})
    with open(os.path.join(evidence_dir, 'summary.json'), 'w',
              encoding='utf-8') as handle:
        json.dump({'manifest': manifest, 'results': all_rows}, handle,
                  ensure_ascii=False, indent=2, sort_keys=True)
        handle.write('\n')
    failed = [row for row in all_rows if row['status'] == 'FAIL']
    completed_rounds = len(glob.glob(os.path.join(evidence_dir,
                                                  'round-*.json')))
    print('[EVIDENCE] %s' % evidence_dir, flush=True)
    print('[SUMMARY] rounds=%d/3 failures=%d' % (
        completed_rounds, len(failed)), flush=True)
    return EXIT_PASS if completed_rounds == 3 and not failed else EXIT_FAIL


if __name__ == '__main__':
    sys.exit(main())
