# -*- coding: utf-8 -*-
"""fakenet-GUI entry point (plan v0.2 §4/§5.4)."""

import sys

from fakenet.gui import startup_logging


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

    try:
        import tkinter as tk
        from tkinter import messagebox
    except ImportError:
        logger.exception('fakenet-GUI 无法导入 tkinter')
        sys.stderr.write(
            'fakenet-GUI 需要 tkinter(当前 Python 未包含)。\n'
            'Windows: 勾选 tcl/tk 组件重装 Python;Linux: 安装 '
            'python3-tk 包。\n')
        logger.info('fakenet-GUI exiting: rc=1')
        return 1

    try:
        _enable_dpi_awareness()
        root = tk.Tk()
        from fakenet.gui.app import FakenetConfigApp
        FakenetConfigApp(root)
        logger.info('fakenet-GUI main window initialized')
    except Exception as exc:  # noqa: BLE001 - fatal dialog, then exit
        logger.exception('fakenet-GUI startup failed')
        try:
            if 'root' in locals():
                root.withdraw()
            messagebox.showerror('fakenet-GUI 启动失败', str(exc))
        finally:
            if 'root' in locals():
                root.destroy()
        raise
    try:
        root.mainloop()
        return 0
    except BaseException:
        logger.exception('fakenet-GUI main loop failed')
        raise
    finally:
        logger.info('fakenet-GUI exiting')


if __name__ == '__main__':
    sys.exit(main())
