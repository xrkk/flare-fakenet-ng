# -*- coding: utf-8 -*-
"""GUI import smoke test (plan v0.2 §6): no window is opened on CI."""

import os
import codecs
import hashlib
import time

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


def _wait_until(root, predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        root.update()
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError('condition did not become true before timeout')


def test_five_tabs_are_named_and_built_lazily():
    root, application = _construct_app()
    try:
        assert [application.notebook.tab(frame, 'text')
                for frame in application._tab_frames] == [
                    '基础配置', '出站策略', '监听器', '自定义响应', '实时日志']
        assert application._tabs_built == {0}
        application.notebook.select(application._tab_frames[4])
        root.update()
        assert application._tabs_built == {0, 4}
    finally:
        root.destroy()


def test_lazy_tab_applies_existing_inline_errors_when_first_opened():
    from fakenet.gui import schema

    root, application = _construct_app()
    try:
        application.model.diverter().set(
            'ExternalAccessPolicy', schema.EGRESS_POLICY_ENABLED)
        application._validate_now()
        assert 1 not in application._tabs_built
        application._ensure_tab(1)
        policy = application._egress_widgets['ExternalAccessPolicy']
        assert policy._error_label is not None
    finally:
        root.destroy()


def test_validation_status_opens_separate_detail_window():
    root, application = _construct_app()
    try:
        _remove_new_config_path_warnings(application)
        application._validate_now()
        assert application._issues == []
        assert application._validation_window is None
        assert application.panel is None

        application.model.diverter().set(
            'DefaultTCPListener', 'MissingListener')
        application._validate_now()
        default_tcp = application._registry[
            ('Diverter', 'defaulttcplistener')]
        assert default_tcp._error_label is not None
        assert '不是已存在' in default_tcp._error_label.cget('text')
        assert application._validation_window is None
        application.open_validation_window()
        root.update_idletasks()
        assert application._validation_window.winfo_exists()
        assert len(application.panel.get_children()) == len(
            application._issues)

        application.model.diverter().set(
            'DefaultTCPListener', 'ProxyTCPListener')
        application._validate_now()
        assert application._issues == []
        assert application.panel.get_children() == ()
    finally:
        root.destroy()


def test_persistent_actions_and_file_status():
    root, application = _construct_app()
    try:
        assert application.notebook.winfo_manager() == 'grid'
        assert application.import_button.winfo_manager() == 'pack'
        assert application.restore_button.winfo_manager() == 'pack'
        assert application.save_button.winfo_manager() == 'pack'
        assert application.launch_button.winfo_manager() == 'pack'
        assert application.import_button.cget('text') == '导入配置'
        assert application.restore_button.cget('text') == '恢复默认配置'
        assert '写回该文件' in application.import_button._hover_help.text
        assert '立即覆盖' in application.restore_button._hover_help.text
        assert application.file_status_var.get() == '○ 新配置尚未保存'

        application._mark_dirty()
        assert application.file_status_var.get().startswith('● 有未保存修改')
    finally:
        root.destroy()


def test_import_button_opens_and_binds_selected_file(tmp_path, monkeypatch):
    from fakenet.gui import app as app_module, configmodel

    path = tmp_path / 'imported.ini'
    imported = configmodel.ConfigModel.new_config()
    imported.diverter().set('DebugLevel', 'Debug')
    imported.save(str(path))

    root, application = _construct_app()
    try:
        monkeypatch.setattr(
            app_module.filedialog, 'askopenfilename',
            lambda **_kwargs: str(path))
        application.import_button.invoke()
        assert application.model.path == os.path.abspath(str(path))
        assert application.model.diverter().get('DebugLevel') == 'Debug'
        assert os.path.abspath(str(path)) in application.file_status_var.get()
        assert not application.dirty
    finally:
        root.destroy()


def test_import_button_respects_unsaved_discard_refusal(monkeypatch):
    from fakenet.gui import app as app_module

    root, application = _construct_app()
    try:
        original = application.model
        application._mark_dirty()
        opened = []
        monkeypatch.setattr(
            app_module.messagebox, 'askyesno',
            lambda *_args, **_kwargs: False)
        monkeypatch.setattr(
            app_module.filedialog, 'askopenfilename',
            lambda **_kwargs: opened.append(True) or '')
        application.import_button.invoke()
        assert application.model is original
        assert application.dirty
        assert opened == []
    finally:
        root.destroy()


def test_restore_defaults_requires_bound_file(monkeypatch):
    from fakenet.gui import app as app_module

    root, application = _construct_app()
    try:
        original = application.model
        warnings = []
        monkeypatch.setattr(
            app_module.messagebox, 'showwarning',
            lambda title, message, **_kwargs:
            warnings.append((title, message)))
        application.restore_button.invoke()
        assert application.model is original
        assert warnings and '尚未绑定文件' in warnings[0][1]
    finally:
        root.destroy()


def test_restore_defaults_cancel_leaves_file_unchanged(tmp_path, monkeypatch):
    from fakenet.gui import app as app_module, configmodel

    path = tmp_path / 'bound.ini'
    bound = configmodel.ConfigModel.new_config()
    bound.diverter().set('DebugLevel', 'Debug')
    bound.save(str(path))
    before = path.read_bytes()

    root, application = _construct_app()
    try:
        application._load_path(str(path))
        original = application.model
        monkeypatch.setattr(
            app_module.messagebox, 'askyesno',
            lambda *_args, **_kwargs: False)
        application.restore_button.invoke()
        assert application.model is original
        assert path.read_bytes() == before
    finally:
        root.destroy()


def test_restore_defaults_write_failure_keeps_current_model(
        tmp_path, monkeypatch):
    from fakenet.gui import app as app_module, configmodel

    path = tmp_path / 'bound.ini'
    bound = configmodel.ConfigModel.new_config()
    bound.save(str(path))

    root, application = _construct_app()
    try:
        application.model = bound
        original = application.model
        errors = []
        monkeypatch.setattr(
            app_module.messagebox, 'askyesno',
            lambda *_args, **_kwargs: True)
        monkeypatch.setattr(
            app_module.messagebox, 'showerror',
            lambda title, message, **_kwargs:
            errors.append((title, message)))

        def fail_save(_model, _path=None):
            raise OSError('write denied')

        monkeypatch.setattr(
            configmodel.ConfigModel, 'save', fail_save)

        application.restore_button.invoke()
        assert application.model is original
        assert errors == [(
            '恢复默认配置', '覆盖配置文件失败:\nwrite denied')]
    finally:
        root.destroy()


@pytest.mark.parametrize(
    ('encoding', 'bom', 'newline'),
    [('utf-8-sig', True, '\n'), ('locale', False, '\r\n')])
def test_restore_defaults_immediately_overwrites_bound_file_and_keeps_format(
        tmp_path, monkeypatch, encoding, bom, newline):
    from fakenet.gui import app as app_module, configmodel, validator

    path = tmp_path / ('bound-%s.ini' % encoding)
    bound = configmodel.ConfigModel.new_config()
    bound.diverter().set('DebugLevel', 'Debug')
    bound.diverter().set('VendorSentinel', 'remove-me')
    bound.encoding = encoding
    bound.bom = bom
    bound.newline = newline
    bound.save(str(path))
    with path.open('ab') as handle:
        handle.write(b'\n# EXTERNAL CHANGE\n')

    root, application = _construct_app()
    try:
        application.model = bound
        application._selected_listener = None
        application._rebuild_all()
        application._clear_dirty()
        custom_before = application.custom_model
        confirmations = []
        monkeypatch.setattr(
            app_module.messagebox, 'askyesno',
            lambda title, message, **_kwargs: confirmations.append(
                (title, message)) or True)

        application.restore_button.invoke()

        raw = path.read_bytes()
        assert confirmations == [(
            '恢复默认配置',
            '将使用默认配置覆盖当前文件:\n%s\n\n'
            '此操作无法撤销,是否继续?' % os.path.abspath(str(path)))]
        assert raw.startswith(b'\xef\xbb\xbf') is bom
        assert (b'\r\n' in raw) is (newline == '\r\n')
        assert application.model.path == os.path.abspath(str(path))
        assert application.model.encoding == encoding
        assert application.model.bom is bom
        assert application.model.newline == newline
        assert application.model.diverter().get('VendorSentinel') is None
        assert application.model.section('ProxyTCPListener') is not None
        assert application.model.section('ProxyUDPListener') is not None
        assert not any(issue.level == 'error'
                       for issue in validator.validate(application.model))
        assert application.custom_model is custom_before
        assert not application.dirty
    finally:
        root.destroy()


def test_custom_response_empty_state_then_editor(monkeypatch):
    root, application = _construct_app()
    try:
        application._ensure_tab(3)
        assert application.custom_empty.winfo_manager() == 'pack'
        assert application.custom_pane.winfo_manager() == ''

        application._custom_new()
        root.update_idletasks()
        assert application.custom_empty.winfo_manager() == 'pack'
        assert '还没有配置段' in application.custom_empty_title_var.get()
        monkeypatch.setattr(application, '_prompt_name',
                            lambda *_args: 'Example')
        application._custom_add()
        root.update_idletasks()
        assert application.custom_empty.winfo_manager() == ''
        assert application.custom_pane.winfo_manager() == 'pack'
    finally:
        root.destroy()


def test_proxy_listener_list_is_full_width_multiline_editor():
    root, application = _construct_app()
    try:
        application._ensure_tab(2)
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
        application._ensure_tab(2)
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


def test_unchanged_focus_out_does_not_mark_configuration_dirty():
    root, application = _construct_app()
    try:
        field = application._registry[('FakeNet', 'diverttraffic')]
        assert not application.dirty
        field._changed()
        assert not application.dirty
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
        application._ensure_tab(2)
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
    from fakenet.gui.app import MAIN_WINDOW_SIZE

    root, application = _construct_app()
    try:
        _remove_new_config_path_warnings(application)
        application._validate_now()
        root.geometry(MAIN_WINDOW_SIZE)
        root.deiconify()
        application.notebook.select(application._tab_frames[0])
        root.update()
        assert application._global_scroll._scrollbar.winfo_manager() == ''

        application._ensure_tab(1)
        application.notebook.select(application._tab_frames[1])
        root.update()
        assert application._egress_scroll._scrollbar.winfo_manager() == ''
    finally:
        root.destroy()


def test_host_visual_density_uses_wide_labels_and_compact_actions():
    root, application = _construct_app()
    try:
        application._render_static_tabs()
        application._ensure_tab(2)
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


def test_egress_policy_checkbox_materializes_locks_and_topology(tmp_path):
    from fakenet.gui import configmodel, schema, validator

    root, application = _construct_app()
    try:
        application._render_static_tabs()
        assert not hasattr(application, '_egress_topology_button')
        policy = application._registry[
            ('Diverter', 'externalaccesspolicy')]
        assert isinstance(policy.input, tkinter.ttk.Checkbutton)
        assert policy.field.label == '出站策略总开关'
        assert policy.get() == schema.EGRESS_POLICY_DISABLED
        policy.input.invoke()
        application._validate_now()

        assert policy.get() == schema.EGRESS_POLICY_ENABLED
        assert application.model.diverter().get(
            'ExternalAccessPolicy') == schema.EGRESS_POLICY_ENABLED
        assert application.model.diverter().get(
            'ExternalAllowedTCPPorts') == '443'
        assert all(application.model.diverter().get(key) == value
                   for key, value in schema.LOCKED_FIELD_VALUES.items())
        assert not [issue for issue in application._issues
                    if issue.level == validator.ERROR]

        enabled = [
            sec for sec in application.model.listener_sections()
            if (sec.get('Enabled') or '').lower() == 'true']
        assert sum((sec.get('Listener') or '') == 'DomainEgressRelay'
                   for sec in enabled) == 1
        assert sum((sec.get('Listener') or '') == 'DNSListener' and
                   (sec.get('Protocol') or '').upper() == 'UDP' and
                   sec.get('Port') == '53' for sec in enabled) == 1
        assert sum((sec.get('Listener') or '') == 'DNSListener' and
                   (sec.get('Protocol') or '').upper() == 'TCP' and
                   sec.get('Port') == '53' for sec in enabled) == 1

        section_count = len(application.model.listener_sections())
        dns_server = application._egress_widgets['ExternalDnsServer']
        dns_server.set('8.8.8.8')
        dns_server._changed()
        application._validate_now()
        assert not [issue for issue in application._issues
                    if issue.level == validator.ERROR]
        assert len(application.model.listener_sections()) == section_count

        enabled_path = tmp_path / 'policy-enabled.ini'
        application.model.save(str(enabled_path))
        assert configmodel.ConfigModel.load(str(enabled_path)).diverter().get(
            'ExternalAccessPolicy') == schema.EGRESS_POLICY_ENABLED

        policy.input.invoke()
        assert policy.get() == schema.EGRESS_POLICY_DISABLED
        assert application.model.diverter().get(
            'ExternalAccessPolicy') == schema.EGRESS_POLICY_DISABLED
        assert application.model.diverter().get(
            'ExternalAllowedTCPPorts') == '443'
        assert sum((sec.get('Listener') or '') == 'DomainEgressRelay'
                   for sec in application.model.listener_sections()) == 1
        disabled_path = tmp_path / 'policy-disabled.ini'
        application.model.save(str(disabled_path))
        assert configmodel.ConfigModel.load(str(disabled_path)).diverter().get(
            'ExternalAccessPolicy') == schema.EGRESS_POLICY_DISABLED
    finally:
        root.destroy()


def test_loading_active_policy_auto_repairs_in_memory_and_marks_dirty(
        tmp_path):
    from fakenet.gui import configmodel, schema, validator

    path = tmp_path / 'active-missing-topology.ini'
    model = configmodel.ConfigModel.new_config()
    model.diverter().set('ExternalAccessPolicy', 'DomainAllowList')
    for key, value in schema.LOCKED_FIELD_VALUES.items():
        model.diverter().set(key, value)
    model.save(str(path))
    before = path.read_bytes()

    root, application = _construct_app()
    try:
        application._load_path(str(path))
        assert path.read_bytes() == before
        assert application.dirty
        assert '未保存修改' in application.file_status_var.get()
        assert not [issue for issue in application._issues
                    if issue.level == validator.ERROR]
    finally:
        root.destroy()


def test_takeover_toggle_materializes_conditional_locked_values(monkeypatch):
    root, application = _construct_app()
    try:
        application._render_static_tabs()
        application._egress_widgets['ExternalAccessPolicy'].input.invoke()
        application.domain_list_widget.set('example.com', notify=True)
        application._egress_widgets['ExternalNonAllowedAction'].set(
            'Drop', notify=True)
        monkeypatch.setattr(tkinter.messagebox, 'askyesno',
                            lambda *_args, **_kwargs: True)
        application.takeover_check.invoke()

        diverter = application.model.diverter()
        assert diverter.get('ExternalAllowedDomains') == 'api.deepseek.com'
        assert diverter.get('ExternalNonAllowedAction') == 'Divert'
        assert 'disabled' in application.domain_list_widget.input.state()
        application.takeover_check.invoke()
        assert 'ExternalTakeoverIPv4' not in diverter
        assert 'disabled' not in application.domain_list_widget.input.state()
    finally:
        root.destroy()


def _widget_disabled(widget):
    try:
        return 'disabled' in widget.state()
    except (AttributeError, TypeError):
        return str(widget.cget('state')) == 'disabled'


def test_lock_is_implicit_badge_free_with_stable_layout():
    root, application = _construct_app()
    try:
        application._render_static_tabs()
        field_widget = application._registry[('Diverter', 'externaldnsserver')]
        children = field_widget.winfo_children()
        layout = [child.grid_info() for child in children]
        base_tip = field_widget._base_tip

        field_widget.set_locked(True)
        assert field_widget.winfo_children() == children
        assert field_widget.tooltip.text == base_tip + '\n🔒 代码强制'
        assert _widget_disabled(field_widget.input)

        field_widget.set_locked(False)
        assert field_widget.winfo_children() == children
        assert [child.grid_info() for child in children] == layout
        assert field_widget.tooltip.text == base_tip
        assert not _widget_disabled(field_widget.input)
    finally:
        root.destroy()


def test_master_switch_off_disables_every_egress_control():
    root, application = _construct_app()
    try:
        application._render_static_tabs()
        switch = application._egress_widgets['ExternalAccessPolicy']
        assert not _widget_disabled(switch.input)
        for key, widget in application._egress_widgets.items():
            if key == 'ExternalAccessPolicy':
                continue
            assert _widget_disabled(widget.input), key
        assert _widget_disabled(application.domain_list_widget.input)
        assert _widget_disabled(application.takeover_check)
        assert _widget_disabled(application.public_ipv4_check)
        assert application.domain_list_widget.tooltip.text.endswith(
            '🔒 出站策略未启用')

        switch.input.invoke()
        assert not _widget_disabled(application.domain_list_widget.input)
        assert not _widget_disabled(application.takeover_check)
        assert not _widget_disabled(
            application._egress_widgets['ExternalNonAllowedAction'].input)
        assert not application.domain_list_widget.tooltip.text.endswith(
            '🔒 出站策略未启用')
    finally:
        root.destroy()


def test_font_and_window_scale_defaults():
    import tkinter.font as tkfont
    from fakenet.gui import app as app_module, widgets as gui_widgets

    root, application = _construct_app()
    try:
        assert root.geometry().split('+')[0] == app_module.MAIN_WINDOW_SIZE
        if 'Microsoft YaHei UI' in tkfont.families(root):
            assert tkfont.nametofont('TkDefaultFont').cget('size') == \
                gui_widgets.scaled(9)
        assert gui_widgets.scaled(9) == 14
    finally:
        root.destroy()


def test_domain_list_and_public_ipv4_table_edit_and_round_trip(
        tmp_path, monkeypatch):
    from fakenet.gui import configmodel

    root, application = _construct_app()
    try:
        application._ensure_tab(1)
        application._egress_widgets['ExternalAccessPolicy'].input.invoke()
        application.domain_list_widget.set('', notify=True)

        domains = iter(('one.example', 'two.example'))
        monkeypatch.setattr(application.domain_list_widget, '_prompt',
                            lambda *_args: next(domains))
        application.domain_list_widget._buttons[0].invoke()
        application.domain_list_widget._buttons[0].invoke()
        assert application.model.diverter().get(
            'ExternalAllowedDomains') == 'one.example, two.example'

        application.public_ipv4_check.invoke()
        monkeypatch.setattr(
            application.public_rules_widget, '_prompt_rule',
            lambda *_args: ('TCP', '203.0.113.7', '443'))
        application.public_rules_widget._buttons[0].invoke()
        expected = 'TCP/203.0.113.7/443'
        assert application.model.diverter().get(
            'ExternalAllowedIPv4Rules') == expected

        path = tmp_path / 'task-editors.ini'
        application.model.save(str(path))
        loaded = configmodel.ConfigModel.load(str(path)).diverter()
        assert loaded.get('ExternalAllowedDomains') == \
            'one.example, two.example'
        assert loaded.get('ExternalAllowedIPv4Rules') == expected

        application.public_ipv4_check.invoke()
        assert 'ExternalAllowedIPv4Rules' not in application.model.diverter()
    finally:
        root.destroy()


def test_process_path_change_automatically_writes_sha256(tmp_path):
    image = tmp_path / 'sample.exe'
    payload = b'MZ\x00fakenet-gui-auto-hash'
    image.write_bytes(payload)

    root, application = _construct_app()
    try:
        application._ensure_tab(1)
        application._egress_widgets['ExternalAccessPolicy'].input.invoke()
        application._egress_widgets[
            'ExternalProcessRedirectEnabled'].input.invoke()
        path_widget = application._egress_widgets[
            'ExternalProcessRedirectImagePath']
        path_widget.set(str(image), notify=True)
        _wait_until(root, lambda: not application._hash_pending)
        expected = hashlib.sha256(payload).hexdigest()
        assert application.model.diverter().get(
            'ExternalProcessRedirectImageSHA256') == expected
        assert application._egress_widgets[
            'ExternalProcessRedirectImageSHA256'].get() == expected
        assert application._hash_issue is None

        application.model.diverter().set(
            'ExternalProcessRedirectImageSHA256', '0' * 64)
        application._start_process_hash(str(image), update_model=False)
        _wait_until(root, lambda: not application._hash_pending)
        assert application._hash_issue is not None
        assert '不一致' in application._hash_issue.message
    finally:
        root.destroy()


def test_disabled_process_redirect_does_not_verify_stale_hash(tmp_path):
    image = tmp_path / 'sample.exe'
    image.write_bytes(b'MZ-disabled')
    root, application = _construct_app()
    try:
        diverter = application.model.diverter()
        diverter.set('ExternalProcessRedirectEnabled', 'No')
        diverter.set('ExternalProcessRedirectImagePath', str(image))
        diverter.set('ExternalProcessRedirectImageSHA256', '0' * 64)
        application._rebuild_all()
        application._ensure_tab(1)
        root.update()
        assert not application._hash_pending
        assert application._hash_issue is None
    finally:
        root.destroy()


def test_system_listeners_are_separate_readonly_and_keep_static_registry():
    root, application = _construct_app()
    try:
        application._render_static_tabs()
        static_widget = application._registry[('Diverter', 'networkmode')]
        application._egress_widgets['ExternalAccessPolicy'].input.invoke()
        application._ensure_tab(2)
        root.update_idletasks()

        system_names = list(application.system_listener_list.get(0, 'end'))
        assert len(system_names) == 3
        assert any('DomainEgressRelay' ==
                   application.model.section(name).get('Listener')
                   for name in system_names)
        application.system_listener_list.selection_set(0)
        application._on_select_system_listener()
        assert application._registry[('Diverter', 'networkmode')] \
            is static_widget
        assert all('disabled' in button.state()
                   for button in application.listener_action_buttons[1:])
        selected = application._selected_listener
        enabled = application._registry[(selected, 'enabled')]
        assert 'disabled' in enabled.input.state()

        relay = next(name for name in system_names
                     if application.model.section(name).get('Listener') ==
                     'DomainEgressRelay')
        application.model.delete_section(relay)
        application._regenerate_system_listeners()
        assert len(application._system_listener_names()) == 3
    finally:
        root.destroy()


def test_running_state_locks_editing_but_keeps_tooltips():
    root, application = _construct_app()
    try:
        application._render_static_tabs()
        field = application._registry[('Diverter', 'networkmode')]
        application._set_running_state(True)
        assert all('disabled' in button.state()
                   for button in application._action_buttons)
        assert 'disabled' in application.launch_button.state()
        assert 'disabled' in field.input.state()
        field.tooltip._enter()
        assert application.hint_var.get() == field.field.hint

        application._set_running_state(False)
        field = application._registry[('Diverter', 'networkmode')]
        assert 'disabled' not in field.input.state()
    finally:
        root.destroy()


def test_live_log_incremental_complete_and_pause_only_stops_autoscroll(
        tmp_path, monkeypatch):
    log_path = tmp_path / 'fakenet.log'
    first = '第一行\n'.encode('utf-8')
    second = '第二行\n'.encode('utf-8')
    log_path.write_bytes(first[:-1])

    root, application = _construct_app()
    try:
        application._ensure_tab(4)
        application._fakenet_log_path = str(log_path)
        application._log_offset = 0
        application._log_decoder = codecs.getincrementaldecoder('utf-8')(
            errors='replace')
        application._log_large_warned = False
        application._running = True
        application._poll_log(schedule=False)
        with log_path.open('ab') as handle:
            handle.write(first[-1:] + second)

        seen = []
        monkeypatch.setattr(application.log_text, 'see', seen.append)
        application.log_pause_var.set(True)
        application._poll_log(schedule=False, final=True)
        text = application.log_text.get('1.0', 'end-1c')
        assert text.encode('utf-8') == first + second
        assert seen == []
        assert application._log_offset == log_path.stat().st_size
    finally:
        root.destroy()


def test_process_exit_finishes_log_and_unlocks_configuration(tmp_path):
    log_path = tmp_path / 'fakenet.log'
    log_path.write_text('done\n', encoding='utf-8')
    root, application = _construct_app()
    try:
        application._ensure_tab(4)
        application._fakenet_log_path = str(log_path)
        application._fakenet_process_handle = 909
        application._log_offset = 0
        application._log_decoder = codecs.getincrementaldecoder('utf-8')(
            errors='replace')
        application._log_large_warned = False
        application._set_running_state(True)
        application._finish_fakenet_session(909, 0, None)
        assert not application._running
        assert application._fakenet_process_handle is None
        assert '退出码 0' in application.log_state_var.get()
        assert application.log_text.get('1.0', 'end-1c') == \
            log_path.read_bytes().decode('utf-8')
        assert all('disabled' not in button.state()
                   for button in application._action_buttons)
    finally:
        root.destroy()


def test_launch_reserves_core_log_beside_selected_fakenet_exe(
        tmp_path, monkeypatch):
    from fakenet.gui import app as app_module

    exe_dir = tmp_path / 'release'
    exe_dir.mkdir()
    exe = exe_dir / 'fakenet.exe'
    exe.write_bytes(b'MZ')
    config = tmp_path / 'bound.ini'

    root, application = _construct_app()
    try:
        application.model.save(str(config))
        application._clear_dirty()
        monkeypatch.setattr(app_module.launcher, 'is_fakenet_running',
                            lambda: False)
        monkeypatch.setattr(app_module.launcher, 'load_settings',
                            lambda: {})
        monkeypatch.setattr(
            app_module.launcher, 'locate_fakenet_exe',
            lambda _settings: (str(exe), 'sibling', ''))
        captured = {}

        def reserve(base_dir=None, **_kwargs):
            captured['base'] = base_dir
            logs = os.path.join(base_dir, 'Logs')
            os.makedirs(logs, exist_ok=True)
            path = os.path.join(logs, 'one.log')
            open(path, 'wb').close()
            return path

        monkeypatch.setattr(
            app_module.startup_logging, 'reserve_fakenet_log_path', reserve)
        monkeypatch.setattr(
            app_module.launcher, 'build_dev_command',
            lambda cfg, log: ('python.exe', '-m fakenet.fakenet', str(tmp_path)))
        monkeypatch.setattr(
            app_module.launcher, 'launch_elevated_with_handle',
            lambda *_args: (True, '已启动', 101))
        monkeypatch.setattr(application, '_begin_fakenet_session',
                            lambda log, handle: captured.update(
                                log=log, handle=handle))

        application._launch_execute()
        assert captured['base'] == str(exe_dir)
        assert os.path.dirname(captured['log']) == str(exe_dir / 'Logs')
        assert captured['handle'] == 101
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
        application._ensure_tab(2)
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
