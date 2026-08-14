# -*- coding: utf-8 -*-
"""GUI import smoke test (plan v0.2 §6): no window is opened on CI."""

import pytest

tkinter = pytest.importorskip('tkinter')


def test_import_app_module():
    from fakenet.gui import app, main, widgets  # noqa: F401


def test_construct_app_and_destroy():
    root = tkinter.Tk()
    root.withdraw()
    try:
        from fakenet.gui.app import FakenetConfigApp
        application = FakenetConfigApp(root)
        root.update_idletasks()
        assert application.model is not None
        assert application.summary_var.get()
    finally:
        root.destroy()
