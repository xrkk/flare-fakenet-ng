# -*- coding: utf-8 -*-
"""Windows launch/lifecycle helpers (plan v1.13 §5.5/§12.17).

Verdicts are fail-closed: an inconclusive VM check refuses the launch
(audit F1).  Duplicate-instance detection approximates the PowerShell
launchers' lock file (Start-EgressControl.ps1:199-210) because
ShellExecuteExW retains the elevated process handle so the GUI can lock the
bound configuration and tail the exact log until FakeNet exits.
"""

import ctypes
import json
import os
import re
import subprocess
import sys
from ctypes import wintypes

VERDICT_VM = 'vm'
VERDICT_PHYSICAL = 'physical'
VERDICT_UNKNOWN = 'unknown'

# Same regex as Start-*.ps1:31.
VM_PATTERN = re.compile(
    r'virtual|vmware|virtualbox|kvm|qemu|hyper-v|xen|parallels', re.I)

SE_ERR_ACCESSDENIED = 5
SW_SHOWNORMAL = 1
SW_RESTORE = 9
SEE_MASK_NOCLOSEPROCESS = 0x00000040
ERROR_CANCELLED = 1223
ERROR_ALREADY_EXISTS = 183
WAIT_OBJECT_0 = 0
WAIT_FAILED = 0xFFFFFFFF
INFINITE = 0xFFFFFFFF
GUI_MUTEX_NAME = r'Local\FLARE_FakeNet_NG_GUI_Config_Tool'
# CHK-002 (REQ-001/CON-001/NON-001): GUI and headless MCP supervisor are
# mutually exclusive. Both sides contend on this shared cross-session mutex
# (the MCP service acquires it in fakenet/mcp/singleinstance.py). Global\
# so the session-0 LocalSystem service sees the user-session GUI.
SHARED_OPERATOR_MUTEX_NAME = r'Global\FakeNet-NG-SoleOperator'

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


def validate_log_path(path):
    """Validate a reserved log path before quoting it for ShellExecuteEx."""
    if not path:
        return False, '日志路径为空'
    if not os.path.isabs(path):
        return False, '日志路径必须为绝对路径(当前 %r)' % path
    if '"' in path:
        return False, '日志路径不得包含引号'
    if any(ord(ch) < 0x20 for ch in path):
        return False, '日志路径不得包含控制字符'
    if path.endswith('\\'):
        return False, '日志路径不得以反斜杠结尾'
    if not os.path.isdir(os.path.dirname(path)):
        return False, '日志目录不存在: %s' % os.path.dirname(path)
    return True, ''


# ---------------------------------------------------------------------------
# Persisted settings (P11: %APPDATA%\fakenet-gui\settings.json)
# ---------------------------------------------------------------------------

def settings_dir(base=None):
    base = base or os.environ.get('APPDATA') or os.path.expanduser('~')
    return os.path.join(base, 'fakenet-gui')


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


def interpret_shell_result(result):
    """Map a ShellExecuteW return code to (ok, detail).

    >32 succeeds; SE_ERR_ACCESSDENIED(5) is the UAC-cancel path.  Split
    out as a pure function so acceptance runners can verify the
    cancel-branch deterministically (clicking 'No' on a real UAC prompt
    cannot be automated).
    """
    if result > 32:
        return True, '已启动'
    if result == SE_ERR_ACCESSDENIED:
        return False, '已取消 UAC 提权,未启动'
    if result == 0:
        return False, '启动失败(ShellExecuteW 返回 0:内存/资源不足)'
    if result == 2:
        return False, '启动失败(ShellExecuteW 返回 2:文件未找到)'
    if result == 3:
        return False, '启动失败(ShellExecuteW 返回 3:路径未找到)'
    return False, '启动失败(ShellExecuteW 返回 %d)' % result


def launch_elevated(target, params, directory=None):
    """ShellExecuteW 'runas'. Returns (ok, detail)."""
    result = _shell_execute(None, 'runas', target, params,
                            directory or os.path.dirname(target) or None,
                            SW_SHOWNORMAL)
    return interpret_shell_result(result)


class _ShellExecuteInfoW(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.DWORD),
        ('fMask', wintypes.ULONG),
        ('hwnd', wintypes.HWND),
        ('lpVerb', wintypes.LPCWSTR),
        ('lpFile', wintypes.LPCWSTR),
        ('lpParameters', wintypes.LPCWSTR),
        ('lpDirectory', wintypes.LPCWSTR),
        ('nShow', ctypes.c_int),
        ('hInstApp', wintypes.HINSTANCE),
        ('lpIDList', ctypes.c_void_p),
        ('lpClass', wintypes.LPCWSTR),
        ('hkeyClass', wintypes.HKEY),
        ('dwHotKey', wintypes.DWORD),
        ('hIconOrMonitor', wintypes.HANDLE),
        ('hProcess', wintypes.HANDLE),
    ]


def _shell_execute_ex(verb, target, params, directory):
    """Return (ok, hinst_value, process_handle, last_error)."""
    if os.name != 'nt':
        return False, 0, None, 0
    shell32 = ctypes.WinDLL('shell32', use_last_error=True)
    execute = shell32.ShellExecuteExW
    execute.argtypes = [ctypes.POINTER(_ShellExecuteInfoW)]
    execute.restype = wintypes.BOOL
    info = _ShellExecuteInfoW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = verb
    info.lpFile = target
    info.lpParameters = params
    info.lpDirectory = directory
    info.nShow = SW_SHOWNORMAL
    ctypes.set_last_error(0)
    ok = bool(execute(ctypes.byref(info)))
    hinst = int(info.hInstApp or 0)
    handle = int(info.hProcess or 0) or None
    return ok, hinst, handle, ctypes.get_last_error()


def launch_elevated_with_handle(target, params, directory=None):
    """Launch elevated and return ``(ok, detail, process_handle)``."""
    ok, hinst, handle, last_error = _shell_execute_ex(
        'runas', target, params,
        directory or os.path.dirname(target) or None)
    if ok and handle:
        return True, '已启动', handle
    if handle:
        close_handle(handle)
    if last_error == ERROR_CANCELLED:
        return False, '已取消 UAC 提权,未启动', None
    if not ok and last_error:
        return False, '启动失败(ShellExecuteExW 错误 %d)' % last_error, None
    launched, detail = interpret_shell_result(hinst)
    return launched, detail, None


def wait_process(handle):
    """Wait for a Windows process handle and return its exit code."""
    if os.name != 'nt' or not handle:
        return None
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    wait = kernel32.WaitForSingleObject
    wait.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    wait.restype = wintypes.DWORD
    result = wait(wintypes.HANDLE(handle), INFINITE)
    if result == WAIT_FAILED:
        raise OSError(ctypes.get_last_error(), 'WaitForSingleObject failed')
    code = wintypes.DWORD()
    get_exit = kernel32.GetExitCodeProcess
    get_exit.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    get_exit.restype = wintypes.BOOL
    if not get_exit(wintypes.HANDLE(handle), ctypes.byref(code)):
        raise OSError(ctypes.get_last_error(), 'GetExitCodeProcess failed')
    return int(code.value)


def close_handle(handle):
    if os.name == 'nt' and handle:
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def acquire_gui_mutex(name=GUI_MUTEX_NAME):
    """Return ``(handle, already_running)`` for the per-session GUI mutex."""
    if os.name != 'nt':
        return None, False
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel32.CreateMutexW
    create.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    create.restype = wintypes.HANDLE
    ctypes.set_last_error(0)
    handle = create(None, False, name)
    error = ctypes.get_last_error()
    if not handle:
        raise OSError(error, 'CreateMutexW failed')
    return int(handle), error == ERROR_ALREADY_EXISTS


def acquire_shared_operator_mutex(name=SHARED_OPERATOR_MUTEX_NAME):
    """CHK-002: return ``(handle, mcp_running)`` for the sole-operator mutex.

    ``mcp_running`` true means the headless MCP supervisor (session-0
    service) already holds the shared mutex and the GUI must refuse to
    start. The handle must stay open for the GUI's lifetime; on refusal it
    is closed by the caller.
    """
    if os.name != 'nt':
        return None, False
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel32.CreateMutexW
    create.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    create.restype = wintypes.HANDLE
    ctypes.set_last_error(0)
    handle = create(None, False, name)
    error = ctypes.get_last_error()
    if not handle:
        raise OSError(error, 'CreateMutexW failed')
    return int(handle), error == ERROR_ALREADY_EXISTS


def activate_existing_gui(title_fragment='FakeNet-NG 配置工具'):
    """Restore and activate a visible top-level window containing title."""
    if os.name != 'nt':
        return False
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    found = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND,
                                      wintypes.LPARAM)

    @callback_type
    def callback(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buffer, len(buffer))
        if title_fragment in buffer.value:
            found.append(hwnd)
            return False
        return True

    user32.EnumWindows(callback, 0)
    if not found:
        return False
    hwnd = found[0]
    user32.ShowWindow(hwnd, SW_RESTORE)
    user32.BringWindowToTop(hwnd)
    return bool(user32.SetForegroundWindow(hwnd))


def build_dev_command(config_path, log_path=None):
    """Dev-mode elevated target: python -m fakenet.fakenet (P1).

    log_path is mandatory (plan 2026.08.21-01 I2): the per-session stop flag
    is derived from it and -p removes the final console pause.
    """
    ok, reason = validate_config_path(config_path)
    if not ok:
        raise LaunchError(reason)
    if not log_path:
        raise LaunchError('log_path is required for the dev launch command')
    ok, reason = validate_log_path(log_path)
    if not ok:
        raise LaunchError(reason)
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    params = '-m fakenet.fakenet -c "%s"' % config_path
    params += ' --no-console-output'
    params += ' --log-file "%s"' % log_path
    params += ' -f "%s.stopflag"' % log_path
    params += ' -p'
    return sys.executable, params, repo_root


def build_frozen_command(exe_path, config_path, log_path=None):
    if not log_path:
        raise LaunchError('log_path is required for the frozen launch command')
    ok, reason = validate_config_path(config_path)
    if not ok:
        raise LaunchError(reason)
    params = '-c "%s"' % config_path
    params += ' --no-console-output'
    ok, reason = validate_log_path(log_path)
    if not ok:
        raise LaunchError(reason)
    params += ' --log-file "%s"' % log_path
    params += ' -f "%s.stopflag"' % log_path
    params += ' -p'
    return exe_path, params, os.path.dirname(exe_path)


def manual_command_hint(config_path):
    """Linux / fallback hint (F4, P1: module form, never the script)."""
    return 'python -m fakenet.fakenet -c "%s"' % config_path
