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
        assert application.validation_toggle_button.winfo_manager() == ''

        application.model.diverter().set(
            'DefaultTCPListener', 'MissingListener')
        application._validate_now()
        assert application._validation_expanded
        assert application.validation_toggle_button.winfo_manager() == 'pack'
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


def test_boolean_fields_use_checkboxes_and_preserve_literals():
    root, application = _construct_app()
    try:
        true_false = application._registry[
            ('ProxyTCPListener', 'enabled')]
        application._render_static_tabs()
        yes_no = application._registry[('FakeNet', 'diverttraffic')]
        assert isinstance(yes_no.input, tkinter.ttk.Checkbutton)
        assert isinstance(true_false.input, tkinter.ttk.Checkbutton)

        yes_no.set('Yes')
        assert yes_no.get() == 'Yes'
        yes_no.input.invoke()
        assert yes_no.get() == 'No'
        assert application.model.fakenet().get('DivertTraffic') == 'No'

        true_false.set('True')
        assert true_false.get() == 'True'
        true_false.input.invoke()
        assert true_false.get() == 'False'
        assert application.model.section(
            'ProxyTCPListener').get('Enabled') == 'False'
    finally:
        root.destroy()


def test_enum_combobox_is_content_width_and_left_aligned():
    root, application = _construct_app()
    try:
        application._render_static_tabs()
        network_mode = application._registry[('Diverter', 'networkmode')]
        assert isinstance(network_mode.input, tkinter.ttk.Combobox)
        assert 10 <= int(network_mode.input.cget('width')) <= 32
        assert network_mode.input.grid_info()['sticky'] == 'w'
    finally:
        root.destroy()


def test_static_groups_are_two_column_but_listener_is_single_column():
    root, application = _construct_app()
    try:
        enabled = application._registry[('ProxyTCPListener', 'enabled')]
        protocol = application._registry[('ProxyTCPListener', 'protocol')]
        application._render_static_tabs()
        network_mode = application._registry[('Diverter', 'networkmode')]
        debug_level = application._registry[('Diverter', 'debuglevel')]
        assert network_mode.grid_info()['row'] == debug_level.grid_info()['row']
        assert {network_mode.grid_info()['column'],
                debug_level.grid_info()['column']} == {0, 1}

        image_path = application._registry[
            ('Diverter', 'externalprocessredirectimagepath')]
        assert image_path.grid_info()['columnspan'] == 2

        assert enabled.grid_info()['column'] == 0
        assert protocol.grid_info()['column'] == 0
    finally:
        root.destroy()


def test_compact_static_tabs_hide_unneeded_scrollbars_at_default_size():
    root, application = _construct_app()
    try:
        _remove_new_config_path_warnings(application)
        application._validate_now()
        root.geometry('980x700')
        root.deiconify()
        application.notebook.select(application._global_scroll)
        root.update()
        assert application._global_scroll._scrollbar.winfo_manager() == ''

        application.notebook.select(application._egress_scroll)
        root.update()
        assert application._egress_scroll._scrollbar.winfo_manager() == ''
    finally:
        root.destroy()


def test_host_visual_density_uses_wide_labels_and_compact_actions():
    root, application = _construct_app()
    try:
        application._render_static_tabs()
        assert int(application._registry[
            ('FakeNet', 'diverttraffic')].label.cget('width')) == 20
        assert int(application._registry[
            ('Diverter', 'processwhitelist')].label.cget('width')) == 20
        assert int(application._registry[
            ('Diverter', 'linuxrestrictinterface')].label.cget('width')) == 16

        buttons = application.listener_action_buttons
        assert [button.cget('text') for button in buttons] == [
            '新增', '复制', '改名', '删除']
        assert all(int(button.cget('width')) == 5 for button in buttons)
    finally:
        root.destroy()


def test_field_tooltip_shows_help_and_updates_status_hint():
    root, application = _construct_app()
    try:
        application._render_static_tabs()
        field = application._registry[('Diverter', 'networkmode')]
        tooltip = field.tooltip
        tooltip._enter()
        assert application.hint_var.get() == field.field.hint
        tooltip._show()
        root.update_idletasks()
        assert tooltip.window is not None
        assert field.field.label in tooltip.text
        assert field.field.hint in tooltip.text
        tooltip._leave()
        assert tooltip.window is None
    finally:
        root.destroy()


def test_unknown_listener_extra_key_has_preservation_tooltip():
    root, application = _construct_app()
    try:
        section = application.model.section('ProxyTCPListener')
        section.set('VendorExtension', 'kept verbatim')
        application._selected_listener = section.name
        application._render_listener_panel()

        def descendants(widget):
            for child in widget.winfo_children():
                yield child
                yield from descendants(child)

        helps = [widget._hover_help
                 for widget in descendants(application._listener_inner)
                 if hasattr(widget, '_hover_help')]
        assert any('VendorExtension' in help_.text and
                   '原样写回' in help_.text and
                   '不校验' in help_.text
                   for help_ in helps)
    finally:
        root.destroy()
