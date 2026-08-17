# -*- coding: utf-8 -*-
"""fakenet-GUI entry point (plan v1.13 §12.17)."""

import sys

from fakenet.gui import startup_logging


def _close_splash():
    """Close PyInstaller's optional native splash; harmless in source mode."""
    try:
        import pyi_splash
        if pyi_splash.is_alive():
            pyi_splash.close()
    except (ImportError, RuntimeError):
        pass


def _native_warning(title, message):
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, message, title, 0x30)
    except Exception:  # noqa: BLE001 - final fallback before Tk exists
        sys.stderr.write('%s: %s\n' % (title, message))


def _enable_dpi_awareness():
    """Crisp rendering on high-DPI Windows; failure is cosmetic (F6)."""
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:  # noqa: BLE001 - non-Windows or shcore missing
        pass


def main():
    try:
        logger, _log_path = startup_logging.configure()
    except BaseException as exc:  # fail closed: never run without a log
        sys.stderr.write('fakenet-GUI 无法创建启动日志,已拒绝运行: %s\n'
                         % exc)
        return 1

    mutex_handle = None
    try:
        from fakenet.gui import launcher
        mutex_handle, already_running = launcher.acquire_gui_mutex()
    except BaseException as exc:
        _close_splash()
        logger.exception('fakenet-GUI mutex creation failed')
        _native_warning('fakenet-GUI 启动失败',
                        '无法建立单实例锁,已拒绝运行:\n%s' % exc)
        logger.info('fakenet-GUI exiting: rc=1')
        return 1

    if already_running:
        _close_splash()
        activated = launcher.activate_existing_gui()
        logger.warning('duplicate GUI instance refused: activated=%s',
                       activated)
        if not activated:
            _native_warning('fakenet-GUI 已在运行',
                            '检测到已有实例,但无法激活其窗口。')
        launcher.close_handle(mutex_handle)
        logger.info('fakenet-GUI duplicate exiting: rc=%d',
                    0 if activated else 1)
        return 0 if activated else 1

    try:
        import tkinter as tk
        from tkinter import messagebox
    except ImportError:
        _close_splash()
        logger.exception('fakenet-GUI 无法导入 tkinter')
        sys.stderr.write(
            'fakenet-GUI 需要 tkinter(当前 Python 未包含)。\n'
            'Windows: 勾选 tcl/tk 组件重装 Python;Linux: 安装 '
            'python3-tk 包。\n')
        logger.info('fakenet-GUI exiting: rc=1')
        launcher.close_handle(mutex_handle)
        return 1

    try:
        _enable_dpi_awareness()
        root = tk.Tk()
        from fakenet.gui.app import FakenetConfigApp
        application = FakenetConfigApp(root)
        application.startup_load()
        root.update_idletasks()
        _close_splash()
        logger.info('fakenet-GUI main window initialized')
    except Exception as exc:  # noqa: BLE001 - fatal dialog, then exit
        _close_splash()
        logger.exception('fakenet-GUI startup failed')
        try:
            if 'root' in locals():
                root.withdraw()
            messagebox.showerror('fakenet-GUI 启动失败', str(exc))
        finally:
            if 'root' in locals():
                root.destroy()
            launcher.close_handle(mutex_handle)
        raise
    try:
        root.mainloop()
        return 0
    except BaseException:
        logger.exception('fakenet-GUI main loop failed')
        raise
    finally:
        logger.info('fakenet-GUI exiting')
        launcher.close_handle(mutex_handle)


if __name__ == '__main__':
    sys.exit(main())
