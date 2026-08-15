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


def _construct_app():
    from fakenet.gui.app import FakenetConfigApp

    root = tkinter.Tk()
    root.withdraw()
    application = FakenetConfigApp(root)
    root.update_idletasks()
    return root, application


def _remove_new_config_path_warnings(application):
    proxy = application.model.section('ProxyTCPListener')
    proxy.set('CA_Cert', '')
    proxy.set('CA_Key', '')


def test_validation_drawer_auto_and_manual_states():
    root, application = _construct_app()
    try:
        _remove_new_config_path_warnings(application)
        application._validate_now()
        assert application._issues == []
        assert not application._validation_expanded
        assert application.validation_body.winfo_manager() == ''
        assert application.validation_issue_actions.winfo_manager() == ''

        application.model.diverter().set(
            'DefaultTCPListener', 'MissingListener')
        application._validate_now()
        assert application._validation_expanded
        assert application.validation_body.winfo_manager() == 'pack'
        assert application.validation_issue_actions.winfo_manager() == 'pack'

        application._toggle_validation()
        application._validate_now()
        assert not application._validation_expanded
        assert application._validation_manually_collapsed

        application.model.diverter().set(
            'DefaultTCPListener', 'ProxyTCPListener')
        application._validate_now()
        assert not application._validation_expanded
        assert not application._validation_manually_collapsed
    finally:
        root.destroy()


def test_persistent_actions_and_file_status():
    root, application = _construct_app()
    try:
        assert application.notebook.winfo_manager() == 'grid'
        assert application.save_button.winfo_manager() == 'pack'
        assert application.launch_button.winfo_manager() == 'pack'
        assert application.file_status_var.get() == '○ 新配置尚未保存'

        application._mark_dirty()
        assert application.file_status_var.get().startswith('● 有未保存修改')
    finally:
        root.destroy()


def test_custom_response_empty_state_then_editor():
    root, application = _construct_app()
    try:
        assert application.custom_empty.winfo_manager() == 'pack'
        assert application.custom_pane.winfo_manager() == ''

        application._custom_new()
        root.update_idletasks()
        assert application.custom_empty.winfo_manager() == ''
        assert application.custom_pane.winfo_manager() == 'pack'
    finally:
        root.destroy()


def test_proxy_listener_list_is_full_width_multiline_editor():
    root, application = _construct_app()
    try:
        field = application._registry[
            ('ProxyTCPListener', 'listeners')]
        assert isinstance(field.input, tkinter.Text)
        assert field.get() == application.model.section(
            'ProxyTCPListener').get('Listeners')
        assert field.input.cget('wrap') == 'word'
    finally:
        root.destroy()
