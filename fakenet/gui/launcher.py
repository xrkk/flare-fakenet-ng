# -*- coding: utf-8 -*-
"""Launch pipeline: VM gate, duplicate-instance gate, UAC elevation
(plan v0.2 §5.5).

Verdicts are fail-closed: an inconclusive VM check refuses the launch
(audit F1).  Duplicate-instance detection approximates the PowerShell
launchers' lock file (Start-DomainAllowList.ps1:199-210) because
ShellExecuteW gives us no process handle to manage.
"""

import ctypes
import json
import os
import re
import subprocess
import sys

VERDICT_VM = 'vm'
VERDICT_PHYSICAL = 'physical'
VERDICT_UNKNOWN = 'unknown'

# Same regex as Start-*.ps1:31.
VM_PATTERN = re.compile(
    r'virtual|vmware|virtualbox|kvm|qemu|hyper-v|xen|parallels', re.I)

SE_ERR_ACCESSDENIED = 5
SW_SHOWNORMAL = 1

WINDOWS_ONLY_NOTE = 'VM 检测仅支持 Windows'


class LaunchError(Exception):
    """Refuse to launch; message explains why."""


class VmCheckResult(object):
    def __init__(self, verdict, detail='', manufacturer='', model=''):
        self.verdict = verdict
        self.detail = detail
        self.manufacturer = manufacturer
        self.model = model

    def __repr__(self):
        return '<VmCheckResult %s %r>' % (self.verdict, self.detail)


def parse_vm_state(manufacturer, model):
    """Pure classifier, unit-testable without PowerShell."""
    haystack = '%s %s' % (manufacturer or '', model or '')
    if haystack.strip():
        if VM_PATTERN.search(haystack):
            return VmCheckResult(VERDICT_VM, 'Win32_ComputerSystem 匹配 VM '
                                '特征', manufacturer, model)
        return VmCheckResult(VERDICT_PHYSICAL,
                             '本机识别为物理机(%s / %s)'
                             % (manufacturer, model), manufacturer, model)
    return VmCheckResult(VERDICT_UNKNOWN, '未能取得 Win32_ComputerSystem '
                        '厂商/型号信息')


def query_vm_state(timeout=10):
    """Run the CIM query off the UI thread; never raises."""
    if os.name != 'nt':
        return VmCheckResult(VERDICT_UNKNOWN, WINDOWS_ONLY_NOTE)
    script = ('$cs = Get-CimInstance Win32_ComputerSystem; '
              'Write-Output $cs.Manufacturer; '
              'Write-Output $cs.Model')
    try:
        completed = subprocess.run(
            ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
             '-ExecutionPolicy', 'Bypass', '-Command', script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout, errors='replace',
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return VmCheckResult(VERDICT_UNKNOWN,
                             'VM 检测执行失败(%s)' % exc.__class__.__name__)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or '').strip()
        return VmCheckResult(VERDICT_UNKNOWN,
                             'VM 检测命令失败: %s' % detail[:200])
    lines = [line.strip() for line in completed.stdout.splitlines()
             if line.strip()]
    if len(lines) < 2:
        return VmCheckResult(VERDICT_UNKNOWN, 'VM 检测输出不完整')
    return parse_vm_state(lines[0], lines[1])


def is_fakenet_running(image_name='fakenet.exe', timeout=10):
    """True when a fakenet.exe process exists (or detection fails).

    Byte-level comparison: on CJK Windows ``tasklist`` emits localized
    messages in the OEM code page, which can crash a UTF-8 text-mode
    reader thread and silently yield stdout=None.
    """
    if os.name != 'nt':
        return False
    try:
        completed = subprocess.run(
            ['tasklist', '/FI', 'IMAGENAME eq %s' % image_name,
             '/FO', 'CSV', '/NH'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (OSError, subprocess.TimeoutExpired):
        return True  # conservative: refuse to double-launch
    if completed.returncode != 0 or completed.stdout is None:
        return True
    return image_name.lower().encode('ascii') in completed.stdout.lower()


def validate_config_path(path):
    """(ok, reason). Rejects quotes/control chars/trailing backslash that
    would break the ShellExecuteW parameter string (P9)."""
    if not path:
        return False, '配置路径为空'
    if not os.path.isabs(path):
        return False, '配置路径必须为绝对路径(当前 %r)' % path
    if '"' in path:
        return False, '配置路径不得包含引号'
    if any(ord(ch) < 0x20 for ch in path):
        return False, '配置路径不得包含控制字符'
    if path.endswith('\\'):
        return False, '配置路径不得以反斜杠结尾'
    if not os.path.isfile(path):
        return False, '配置文件不存在: %s' % path
    return True, ''


# ---------------------------------------------------------------------------
# Persisted settings (P11: %APPDATA%\fakenet-config\settings.json)
# ---------------------------------------------------------------------------

def settings_dir(base=None):
    base = base or os.environ.get('APPDATA') or os.path.expanduser('~')
    return os.path.join(base, 'fakenet-config')


def load_settings(base=None):
    path = os.path.join(settings_dir(base), 'settings.json')
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(settings, base=None):
    directory = settings_dir(base)
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, 'settings.json')
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(settings, handle, indent=2, ensure_ascii=True)
    return path


def locate_fakenet_exe(settings=None, base_dir=None):
    """(path or None, source, note).

    Order: valid persisted path -> same-directory fakenet.exe; an invalid
    persisted path falls back to sibling detection with a note (P11).
    """
    settings = settings if settings is not None else load_settings()
    if base_dir is None:
        base_dir = (os.path.dirname(sys.executable)
                    if getattr(sys, 'frozen', False) else
                    os.path.dirname(os.path.dirname(os.path.dirname(
                        os.path.abspath(__file__)))))
    sibling = os.path.join(base_dir, 'fakenet.exe')
    persisted = (settings.get('fakenet_exe') or '').strip()
    if persisted and os.path.isfile(persisted):
        return persisted, 'settings', ''
    if os.path.isfile(sibling):
        note = ''
        if persisted:
            note = ('已保存的 fakenet.exe 路径(%s)无效,回落到同目录探测'
                    % persisted)
        return sibling, 'sibling', note
    return None, 'none', ('未找到 fakenet.exe:请将其放在本工具同一目录,'
                          '或在设置中手工指定路径')


# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------

def _shell_execute(hwnd, verb, file_, params, directory, show):
    if os.name != 'nt':
        return -1
    shell32 = ctypes.windll.shell32
    shell32.ShellExecuteW.argtypes = [
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    return int(shell32.ShellExecuteW(hwnd, verb, file_, params, directory,
                                     show))


def launch_elevated(target, params, directory=None):
    """ShellExecuteW 'runas'. Returns (ok, detail)."""
    result = _shell_execute(None, 'runas', target, params,
                            directory or os.path.dirname(target) or None,
                            SW_SHOWNORMAL)
    if result > 32:
        return True, '已启动'
    if result == SE_ERR_ACCESSDENIED:
        return False, '已取消 UAC 提权,未启动'
    return False, '启动失败(ShellExecuteW 返回 %d)' % result


def build_dev_command(config_path):
    """Dev-mode elevated target: python -m fakenet.fakenet (P1)."""
    ok, reason = validate_config_path(config_path)
    if not ok:
        raise LaunchError(reason)
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    params = '-m fakenet.fakenet -c "%s"' % config_path
    return sys.executable, params, repo_root


def build_frozen_command(exe_path, config_path):
    ok, reason = validate_config_path(config_path)
    if not ok:
        raise LaunchError(reason)
    return exe_path, '-c "%s"' % config_path, os.path.dirname(exe_path)


def manual_command_hint(config_path):
    """Linux / fallback hint (F4, P1: module form, never the script)."""
    return 'python -m fakenet.fakenet -c "%s"' % config_path
