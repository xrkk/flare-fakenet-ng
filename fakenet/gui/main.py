# -*- coding: utf-8 -*-
"""fakenet-config entry point (plan v0.2 §4/§5.4)."""

import sys


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
        import tkinter as tk
        from tkinter import messagebox
    except ImportError:
        sys.stderr.write(
            'fakenet-config 需要 tkinter(当前 Python 未包含)。\n'
            'Windows: 勾选 tcl/tk 组件重装 Python;Linux: 安装 '
            'python3-tk 包。\n')
        return 1

    _enable_dpi_awareness()
    root = tk.Tk()
    try:
        from fakenet.gui.app import FakenetConfigApp
        FakenetConfigApp(root)
    except Exception as exc:  # noqa: BLE001 - fatal dialog, then exit
        try:
            root.withdraw()
            messagebox.showerror('fakenet-config 启动失败', str(exc))
        finally:
            root.destroy()
        raise
    root.mainloop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
