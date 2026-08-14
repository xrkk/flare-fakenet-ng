# -*- coding: utf-8 -*-
"""One-click GUI VM acceptance runner (plan v0.2 §12.4 pending item).

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


def main():
    global LOG_DIR

    if os.name != 'nt':
        return refuse('仅支持 Windows')
    if not is_admin():
        return refuse('未提权:请通过 Run-Tests.cmd 启动(会自动请求提权,'
                      '此后全程免操作)')

    stamp = time.strftime('%Y%m%d-%H%M%S')
    LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'Logs', stamp)
    os.makedirs(LOG_DIR, exist_ok=True)
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
        if not appeared:
            result('A6 提权启动', 'FAIL',
                   '已发起但 40 秒内未见 fakenet.exe 存活')
        else:
            result('A6 提权启动', 'PASS',
                   'fakenet.exe: %s%s' % (
                       fakenet_exe, ';日志已写入' if log_ready
                       else '(日志未就绪)'))

        if launcher.is_fakenet_running():
            result('A7 双实例门', 'PASS',
                   '真实 fakenet.exe 运行中被 is_fakenet_running 检出'
                   '(GUI 启动门将拒绝二次启动)')
        else:
            result('A7 双实例门', 'FAIL', '实例存活但未被检出')

        with open(stop_flag, 'w') as handle:
            handle.write('stop\n')
        stopped = wait_for(lambda: not launcher.is_fakenet_running(), 40)
        if stopped:
            result('A8 停止旗标优雅停止', 'PASS',
                   'stop flag 触发 fakenet 自行退出;-l 日志: %s'
                   % fakenet_log)
        else:
            result('A8 停止旗标优雅停止', 'FAIL', '40 秒内未退出,强制清理')
            subprocess.run(['taskkill', '/F', '/IM', 'fakenet.exe'],
                           capture_output=True)

    # -- A9 GUI launch smoke ----------------------------------------------------
    gui_exe = find_file('fakenet-config.exe')
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
        gui_proc.terminate()
        gui_proc.wait(timeout=10)
    except Exception as exc:  # noqa: BLE001 - recorded as evidence
        alive = False
        result('A9 GUI 启动冒烟', 'FAIL', '异常: %s' % exc)
    else:
        result('A9 GUI 启动冒烟', 'PASS' if alive else 'FAIL',
               '模式 %s;%s' % (gui_mode,
                               '6 秒后仍存活(无崩溃)' if alive else
                               '启动后即退出'))

    return finish()


def finish():
    failed = [r for r in RESULTS if r[0] == 'FAIL']
    print('\n===== 汇总: %d 项,失败 %d 项 =====' % (len(RESULTS), len(failed)))
    for status, name, detail, level in RESULTS:
        print('  %-6s %-24s %s' % (status, name, detail))
    print('明细: %s' % os.path.join(LOG_DIR, 'results.tsv'))
    return EXIT_FAIL if failed else EXIT_PASS


if __name__ == '__main__':
    sys.exit(main())
