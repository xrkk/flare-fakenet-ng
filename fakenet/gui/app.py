# -*- coding: utf-8 -*-
"""fakenet-GUI main window (plan v1.10 §5.4/§12.14).

Chinese UI.  Tabs: 全局 ([FakeNet] + [Diverter] base groups), 出站策略
(egress sub-groups with smart locking and topology auto-fix), 监听器
(section list + dynamic field panel), 自定义响应.  Collapsible validation
drawer with double-click jump-to-field; persistent import/restore/save +
launch bar.  The launch pipeline runs VM/duplicate gates off the UI thread
and is fail-closed on inconclusive VM state.
"""

import os
import sys
import textwrap
import threading
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox

from fakenet.gui import configmodel, launcher, schema, validator, widgets

APP_TITLE = 'FakeNet-NG 配置工具'
TEMPLATE_EXCLUDE = ('sample_custom_response.ini',)
VALIDATE_DEBOUNCE_MS = 300

COLOR_BG = '#F4F6F8'
COLOR_MUTED = '#5F6B7A'
COLOR_PRIMARY = '#1769AA'
COLOR_SUCCESS = '#18864B'
COLOR_WARNING = '#B7791F'
COLOR_ERROR = '#C9362B'


def configure_styles(root):
    """Apply a restrained Windows analysis-workbench visual system."""
    available = set(tkfont.families(root))
    if 'Microsoft YaHei UI' in available:
        for name in ('TkDefaultFont', 'TkTextFont', 'TkMenuFont',
                     'TkHeadingFont'):
            try:
                tkfont.nametofont(name).configure(
                    family='Microsoft YaHei UI', size=9)
            except tk.TclError:
                pass
    root.configure(background=COLOR_BG)
    style = ttk.Style(root)
    style.configure('TNotebook.Tab', padding=(12, 5))
    style.configure('TLabelframe', padding=(4, 4))
    style.configure('Muted.TLabel', foreground=COLOR_MUTED)
    style.configure('Locked.TLabel', foreground=COLOR_MUTED)
    style.configure('Success.TLabel', foreground=COLOR_SUCCESS,
                    font=('', 9, 'bold'))
    style.configure('Warning.TLabel', foreground=COLOR_WARNING,
                    font=('', 9, 'bold'))
    style.configure('Error.TLabel', foreground=COLOR_ERROR,
                    font=('', 9, 'bold'))
    style.configure('Primary.TButton', padding=(12, 6),
                    foreground=COLOR_PRIMARY, font=('', 9, 'bold'))
    style.configure('Action.TButton', padding=(10, 5))
    return style


def scrollable(parent):
    """Canvas + scrollbar wrapper returning the inner frame.

    The wheel handler is re-pointed on Enter/Leave so several scrollable
    tabs don't fight over the global <MouseWheel> binding.
    """
    container = ttk.Frame(parent)
    canvas = tk.Canvas(container, highlightthickness=0)
    bar = ttk.Scrollbar(container, orient='vertical', command=canvas.yview)
    inner = ttk.Frame(canvas)
    window = canvas.create_window((0, 0), window=inner, anchor='nw')
    canvas.configure(yscrollcommand=bar.set)
    canvas.pack(side='left', fill='both', expand=True)

    def update_scrollbar():
        if not canvas.winfo_exists():
            return
        needed = inner.winfo_reqheight() > canvas.winfo_height() + 1
        if needed and not bar.winfo_manager():
            bar.pack(side='right', fill='y')
        elif not needed and bar.winfo_manager():
            bar.pack_forget()

    def inner_changed(_event=None):
        canvas.configure(scrollregion=canvas.bbox('all'))
        canvas.after_idle(update_scrollbar)

    def canvas_changed(event):
        canvas.itemconfigure(window, width=event.width)
        canvas.after_idle(update_scrollbar)

    inner.bind('<Configure>', inner_changed)
    canvas.bind('<Configure>', canvas_changed)
    container._scroll_canvas = canvas
    container._scrollbar = bar
    container._scroll_inner = inner

    def wheel(event):
        first, last = canvas.yview()
        if last - first < 1:
            return
        canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')

    container.bind('<Enter>', lambda _e: canvas.bind_all('<MouseWheel>',
                                                         wheel))
    container.bind('<Leave>', lambda _e: canvas.unbind_all('<MouseWheel>'))
    return container, inner


class FakenetConfigApp(object):

    def __init__(self, root):
        self.root = root
        self.model = None
        self.dirty = False
        self._validate_job = None
        self._issues = []
        self._registry = {}       # (section, key) -> FieldWidget
        self._egress_widgets = {}
        self._selected_listener = None
        self._building = False
        self._validation_expanded = False
        self._validation_manually_collapsed = False

        root.title(APP_TITLE)
        root.geometry('980x700')
        root.minsize(900, 640)
        configure_styles(root)
        self._build_menu()
        self._build_layout()
        self.new_config()
        root.protocol('WM_DELETE_WINDOW', self._on_close)

    # ------------------------------------------------------------------
    # menus / layout
    # ------------------------------------------------------------------

    def _build_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label='新建', command=self.new_config)
        file_menu.add_command(label='打开…', command=self.open_file)
        file_menu.add_command(label='保存', command=self.save,
                              accelerator='Ctrl+S')
        file_menu.add_command(label='另存为…', command=lambda:
                              self.save(as_else=True))
        file_menu.add_separator()
        file_menu.add_command(label='退出', command=self._on_close)
        menubar.add_cascade(label='文件', menu=file_menu)

        self.template_menu = tk.Menu(menubar, tearoff=0)
        self.template_menu.add_command(
            label='(刷新清单)', command=self._refresh_templates)
        menubar.add_cascade(label='模板载入', menu=self.template_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label='关于', command=self._about)
        menubar.add_cascade(label='帮助', menu=help_menu)
        self.root.config(menu=menubar)
        self.root.bind('<Control-s>', lambda _e: self.save())
        self.root.after_idle(self._refresh_templates)

    def _template_dirs(self):
        if getattr(configmodel, 'FROZEN', False) or \
                getattr(sys, 'frozen', False):
            candidates = [os.path.join(os.path.dirname(sys.executable),
                                       'configs')]
        else:
            candidates = [
                os.path.join(os.path.dirname(os.path.dirname(
                    os.path.dirname(os.path.abspath(__file__)))),
                    'fakenet', 'configs'),
                os.path.join(os.path.dirname(sys.executable), 'configs'),
            ]
        return [d for d in candidates if os.path.isdir(d)]

    def _refresh_templates(self):
        self.template_menu.delete(0, 'end')
        names = []
        for directory in self._template_dirs():
            for name in sorted(os.listdir(directory)):
                if name.endswith('.ini') and name not in TEMPLATE_EXCLUDE:
                    if name not in names:
                        names.append(name)
        if not names:
            self.template_menu.add_command(
                label='(未找到配置目录)', state='disabled')
            return
        for name in names:
            self.template_menu.add_command(
                label=name, command=lambda n=name: self.load_template(n))

    def _build_layout(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        top = ttk.Frame(self.root, padding=(10, 7, 10, 2))
        top.grid(row=0, column=0, sticky='ew')
        self.summary_var = tk.StringVar(value='就绪')
        self.summary_label = ttk.Label(
            top, textvariable=self.summary_var, style='Success.TLabel')
        self.summary_label.pack(side='left')
        self.hint_var = tk.StringVar(value='')
        ttk.Label(top, textvariable=self.hint_var, style='Muted.TLabel')\
            .pack(side='left', padx=16)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=1, column=0, sticky='nsew', padx=8,
                           pady=(4, 4))
        self._build_global_tab()
        self._build_egress_tab()
        self._build_listeners_tab()
        self._build_custom_tab()

        validation = ttk.Frame(self.root, padding=(8, 0, 8, 4))
        validation.grid(row=2, column=0, sticky='ew')
        panel_header = ttk.Frame(validation)
        panel_header.pack(fill='x')
        self.validation_summary_var = tk.StringVar(value='✓ 校验通过')
        self.validation_summary_label = ttk.Label(
            panel_header, textvariable=self.validation_summary_var,
            style='Success.TLabel')
        self.validation_summary_label.pack(side='left', padx=(4, 8))
        ttk.Label(
            panel_header,
            text='双击跳转 · 右键/Ctrl+C 复制',
            style='Muted.TLabel').pack(side='left')
        self.validation_toggle_button = ttk.Button(
            panel_header, text='展开详情', width=9,
            command=self._toggle_validation)
        self.validation_toggle_button.pack(side='right')
        self.validation_issue_actions = ttk.Frame(panel_header)
        self.validation_issue_actions.pack(side='right', padx=(4, 0))
        self.copy_all_button = ttk.Button(
            self.validation_issue_actions, text='复制全部', width=9,
            command=self._copy_all_issues)
        self.copy_all_button.pack(side='right')
        self.copy_selected_button = ttk.Button(
            self.validation_issue_actions, text='复制选中', width=9,
            command=self._copy_selected_issues)
        self.copy_selected_button.pack(side='right', padx=(4, 0))

        self.validation_body = ttk.Frame(validation)
        self.panel = ttk.Treeview(self.validation_body, height=6,
                                  columns=('level', 'loc', 'msg'),
                                  show='headings',
                                  selectmode='extended')
        self.panel.heading('level', text='级别')
        self.panel.heading('loc', text='位置')
        self.panel.heading('msg', text='消息')
        self.panel.column('level', width=48, minwidth=48, stretch=False)
        self.panel.column('loc', width=240, minwidth=240, stretch=False)
        # Full text stays intact in the item values; the wide minwidth +
        # horizontal scrollbar make it reachable instead of clipped.
        self.panel.column('msg', width=1200, minwidth=680, stretch=False)
        xbar = ttk.Scrollbar(self.validation_body, orient='horizontal',
                             command=self.panel.xview)
        ybar = ttk.Scrollbar(self.validation_body, orient='vertical',
                             command=self.panel.yview)
        self.panel.configure(xscrollcommand=xbar.set,
                             yscrollcommand=ybar.set)
        ybar.pack(side='right', fill='y')
        self.panel.pack(side='top', fill='x', expand=True)
        xbar.pack(side='bottom', fill='x')
        self.panel.bind('<Double-1>', self._jump_to_issue)
        self.panel.bind('<Button-3>', self._panel_popup)
        self.panel.bind('<Control-c>', self._copy_selected_and_break)

        self._panel_menu = tk.Menu(self.root, tearoff=0)
        self._panel_menu.add_command(label='复制选中行 (Ctrl+C)',
                                     command=self._copy_selected_issues)
        self._panel_menu.add_command(label='复制全部',
                                     command=self._copy_all_issues)
        self._panel_menu.add_separator()
        self._panel_menu.add_command(label='查看完整消息…',
                                     command=self._show_full_issue)

        ttk.Separator(self.root).grid(row=3, column=0, sticky='ew')
        action_bar = ttk.Frame(self.root, padding=(10, 7, 10, 9))
        action_bar.grid(row=4, column=0, sticky='ew')
        self.file_status_var = tk.StringVar(value='未保存配置')
        ttk.Label(action_bar, textvariable=self.file_status_var,
                  style='Muted.TLabel').pack(side='left', fill='x',
                                             expand=True)
        self.launch_button = ttk.Button(
            action_bar, text='▶ 启动 FakeNet-NG', style='Primary.TButton',
            command=self.launch)
        self.launch_button.pack(side='right')
        self.save_button = ttk.Button(
            action_bar, text='保存配置', style='Action.TButton',
            command=self.save)
        self.save_button.pack(side='right', padx=(0, 8))
        self.restore_button = ttk.Button(
            action_bar, text='恢复默认配置', command=self.restore_defaults)
        self.restore_button.pack(side='right', padx=(0, 8))
        self.import_button = ttk.Button(
            action_bar, text='导入配置', command=self.open_file)
        self.import_button.pack(side='right', padx=(0, 8))
        widgets.attach_tooltip(
            self.import_button,
            '导入配置\n打开并编辑现有 INI;保存配置时将写回该文件。',
            self._hint, '打开并绑定现有 INI;保存时写回原文件')
        widgets.attach_tooltip(
            self.restore_button,
            '恢复默认配置\n确认后使用安全默认配置立即覆盖当前绑定的 INI 文件。',
            self._hint, '确认后立即覆盖当前绑定文件')

        self._set_validation_expanded(False)

    # ------------------------------------------------------------------
    # tab builders
    # ------------------------------------------------------------------

    def _build_global_tab(self):
        container, inner = scrollable(self.notebook)
        self.notebook.add(container, text='全局')
        self._global_scroll = container
        self._global_inner = inner

    def _build_egress_tab(self):
        container, inner = scrollable(self.notebook)
        self.notebook.add(container, text='出站策略')
        self._egress_scroll = container
        inner.columnconfigure(0, weight=1, uniform='egress-group')
        inner.columnconfigure(1, weight=1, uniform='egress-group')
        self._egress_topology_button = ttk.Button(
            inner, text='一键补齐必需监听器(DomainEgressRelay + 2×DNS)',
            command=self.autofix_topology)
        self._egress_topology_button.grid(
            row=0, column=0, columnspan=2, sticky='w', padx=4, pady=3)
        widgets.attach_tooltip(
            self._egress_topology_button,
            '一键补齐必需监听器\n创建或启用 1 个 DomainEgressRelay、'
            'UDP/53 与 TCP/53 各 1 个 DNSListener;私网接管时仅补空的 '
            'ResponseA。此按钮不会启用出站策略。',
            self._hint, '补齐 DomainAllowList 必需的 relay 与 DNS 监听器')
        self._egress_inner = inner

    def _build_listeners_tab(self):
        pane = ttk.PanedWindow(self.notebook, orient='horizontal')
        self.notebook.add(pane, text='监听器')

        left = ttk.Frame(pane, padding=(2, 0, 4, 0))
        pane.add(left, weight=1)
        self.listener_list = tk.Listbox(left, width=22, exportselection=False)
        self.listener_list.pack(fill='both', expand=True)
        self.listener_list.bind('<<ListboxSelect>>', self._on_select_listener)
        buttons = ttk.Frame(left)
        buttons.pack(fill='x')
        self.listener_action_buttons = []
        for text, command in (
                ('新增', self._listener_add),
                ('复制', self._listener_duplicate),
                ('改名', self._listener_rename),
                ('删除', self._listener_delete)):
            button = ttk.Button(buttons, text=text, width=5,
                                command=command)
            button.pack(side='left', padx=1)
            self.listener_action_buttons.append(button)

        right_container, right = scrollable(pane)
        pane.add(right_container, weight=5)
        self._listener_inner = right
        self.expansion_var = tk.StringVar(value='')
        ttk.Label(right, textvariable=self.expansion_var,
                  style='Muted.TLabel').pack(anchor='w')

    def _build_custom_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text='自定义响应')
        bar = ttk.Frame(tab)
        bar.pack(fill='x', padx=6, pady=6)
        ttk.Button(bar, text='打开响应文件…', style='Action.TButton',
                   command=self._custom_open).pack(side='left')
        ttk.Button(bar, text='新建响应文件', style='Action.TButton',
                   command=self._custom_new).pack(side='left', padx=4)
        ttk.Button(bar, text='保存响应文件', style='Action.TButton',
                   command=self._custom_save)\
            .pack(side='left')
        self.custom_status = tk.StringVar(value='未加载(由监听器的 Custom 键引用)')
        ttk.Label(bar, textvariable=self.custom_status,
                  style='Muted.TLabel').pack(side='left', padx=12)

        self.custom_empty = ttk.Frame(tab, padding=(24, 70))
        ttk.Label(self.custom_empty, text='尚未加载自定义响应文件',
                  font=('', 11, 'bold')).pack()
        ttk.Label(
            self.custom_empty,
            text='自定义响应文件由监听器中的 Custom 字段引用。\n'
                 '请打开已有 INI，或新建一个响应文件后添加配置段。',
            justify='center', style='Muted.TLabel').pack(pady=(10, 0))

        self.custom_pane = ttk.PanedWindow(tab, orient='horizontal')
        left = ttk.Frame(self.custom_pane, padding=(2, 0, 4, 0))
        self.custom_pane.add(left, weight=1)
        self.custom_list = tk.Listbox(left, width=28, exportselection=False)
        self.custom_list.pack(fill='both', expand=True)
        self.custom_list.bind('<<ListboxSelect>>', self._on_select_custom)
        addbox = ttk.Frame(left)
        addbox.pack(fill='x')
        ttk.Button(addbox, text='新增段', width=8,
                   command=self._custom_add).pack(side='left', padx=1)
        ttk.Button(addbox, text='删除段', width=8,
                   command=self._custom_delete).pack(side='left', padx=1)

        right_container, right = scrollable(self.custom_pane)
        self.custom_pane.add(right_container, weight=3)
        self._custom_inner = right
        self.custom_model = None
        self._custom_selected = None
        self._custom_registry = {}
        self._update_custom_content_state()

    # ------------------------------------------------------------------
    # model wiring
    # ------------------------------------------------------------------

    def _hint(self, text):
        self.hint_var.set(text)

    def _set_validation_expanded(self, expanded, manual=False):
        expanded = bool(expanded)
        if manual:
            self._validation_manually_collapsed = not expanded
        if expanded == self._validation_expanded:
            return
        self._validation_expanded = expanded
        if expanded:
            self.validation_body.pack(fill='x', pady=(4, 0))
            self.validation_toggle_button.configure(text='收起详情')
        else:
            self.validation_body.pack_forget()
            self.validation_toggle_button.configure(text='展开详情')

    def _toggle_validation(self):
        if not self._issues:
            return
        self._set_validation_expanded(
            not self._validation_expanded, manual=True)

    def _update_file_status(self):
        if self.model is None:
            text = '未加载配置'
        else:
            path = self.model.path or '未保存配置'
            text = ('● 有未保存修改 · %s' if self.dirty else
                    '✓ 已保存 · %s') % path
            if not self.model.path and not self.dirty:
                text = '○ 新配置尚未保存'
        self.file_status_var.set(text)

    def _mark_dirty(self):
        self.dirty = True
        name = os.path.basename(self.model.path) if self.model.path \
            else '未命名'
        self.root.title('%s* - %s' % (name, APP_TITLE))
        self._update_file_status()

    def _clear_dirty(self):
        self.dirty = False
        name = os.path.basename(self.model.path) if self.model.path \
            else '未命名'
        self.root.title('%s - %s' % (name, APP_TITLE))
        self._update_file_status()

    def _schedule_validate(self):
        if self._validate_job is not None:
            self.root.after_cancel(self._validate_job)
        self._validate_job = self.root.after(VALIDATE_DEBOUNCE_MS,
                                             self._validate_now)

    def _validate_now(self):
        self._validate_job = None
        if self.model is None:
            return
        self._issues = validator.validate(self.model)
        errors = [i for i in self._issues if i.level == validator.ERROR]
        warns = [i for i in self._issues if i.level == validator.WARNING]
        self.summary_var.set('⚠ %d 错误 / %d 警告' % (len(errors), len(warns))
                             if (errors or warns) else '✓ 校验通过')
        if errors:
            style = 'Error.TLabel'
            detail = '✕ %d 个错误 / %d 个警告' % (len(errors), len(warns))
        elif warns:
            style = 'Warning.TLabel'
            detail = '⚠ 0 个错误 / %d 个警告' % len(warns)
        else:
            style = 'Success.TLabel'
            detail = '✓ 校验通过'
        self.summary_label.configure(style=style)
        self.validation_summary_label.configure(style=style)
        self.validation_summary_var.set(detail)
        self.launch_button.state(['!disabled'] if not errors
                                 else ['disabled'])
        self.panel.delete(*self.panel.get_children())
        for issue in errors + warns:
            self.panel.insert('', 'end',
                              values=('错误' if issue.level == validator.ERROR
                                      else '警告',
                                      issue.location, issue.message))
        button_state = ['!disabled'] if self._issues else ['disabled']
        self.validation_toggle_button.state(button_state)
        self.copy_all_button.state(button_state)
        self.copy_selected_button.state(button_state)
        if self._issues:
            if not self.validation_toggle_button.winfo_manager():
                self.validation_toggle_button.pack(side='right')
            if not self.validation_issue_actions.winfo_manager():
                self.validation_issue_actions.pack(
                    side='right', padx=(4, 0),
                    before=self.validation_toggle_button)
            if not self._validation_manually_collapsed:
                self._set_validation_expanded(True)
        else:
            self.validation_issue_actions.pack_forget()
            self.validation_toggle_button.pack_forget()
            self._validation_manually_collapsed = False
            self._set_validation_expanded(False)
        self._refresh_locks()

    def _refresh_locks(self):
        if self.model is None:
            return
        diverter = self.model.diverter()
        policy = (diverter.get('ExternalAccessPolicy') or
                   'Disabled').strip().lower() == 'domainallowlist'
        takeover = bool((diverter.get('ExternalTakeoverIPv4') or '').strip())
        self._egress_topology_button.state(
            ['!disabled'] if policy else ['disabled'])
        for key, widget in self._egress_widgets.items():
            field = schema.diverter_field(key)
            if field is None:
                continue
            if field.key == 'ExternalAccessPolicy':
                widget.set_locked(False)
            elif field.lock:
                widget.set_locked(policy)  # pinned values, read-only badge
            elif field.cond_lock == schema.COND_TAKEOVER_DOMAINS:
                if policy and takeover:
                    widget.set_locked(True, forced_value='api.deepseek.com')
                else:
                    widget.set_locked(False)
            elif field.cond_lock == schema.COND_TAKEOVER_ACTION:
                if policy and takeover:
                    widget.set_locked(True, forced_value='Divert')
                else:
                    widget.set_locked(False)
            else:
                widget.set_locked(not policy)

    def _sync_active_egress_locks(self):
        """Write UI-enforced values after an explicit egress edit."""
        diverter = self.model.diverter()
        policy = (diverter.get('ExternalAccessPolicy') or
                  'Disabled').strip().lower() == 'domainallowlist'
        if not policy:
            return
        values = dict(schema.LOCKED_FIELD_VALUES)
        if (diverter.get('ExternalTakeoverIPv4') or '').strip():
            values.update({
                'ExternalAllowedDomains': 'api.deepseek.com',
                'ExternalNonAllowedAction': 'Divert',
            })
        for key, value in values.items():
            if diverter.get(key) != value:
                diverter.set(key, value)
            widget = self._egress_widgets.get(key)
            if widget is not None and widget.get() != value:
                widget.set(value)

    # ------------------------------------------------------------------
    # global / egress tabs render
    # ------------------------------------------------------------------

    def _render_static_tabs(self):
        for child in self._global_inner.winfo_children():
            child.destroy()
        for child in self._egress_inner.winfo_children():
            if child is not self._egress_topology_button:
                child.destroy()
        self._egress_widgets = {}
        self._registry = {}
        for column in range(2):
            self._global_inner.columnconfigure(
                column, weight=1, uniform='global-group')

        def getter(section):
            return lambda key: (self.model.section(section).get(key, '') or
                                '')

        def on_change(section):
            def handler(key, value):
                if self._building:
                    return
                self.model.section(section).set(key, value)
                field = schema.diverter_field(key) \
                    if section == 'Diverter' else None
                if field and field.group in schema.egress_group_names():
                    self._sync_active_egress_locks()
                    self._refresh_locks()
                self._mark_dirty()
                self._schedule_validate()
            return handler

        fakenet_frame = widgets.build_group_frame(
            self._global_inner, '[FakeNet]', schema.FAKENET_FIELDS,
            getter('FakeNet'), on_change('FakeNet'), self._hint,
            self._registry, 'FakeNet', columns=2, label_width=20)
        fakenet_frame.grid(row=0, column=0, sticky='nsew', padx=3, pady=3)

        base_groups = {}
        for field in schema.DIVERTER_FIELDS:
            if field.group in schema.egress_group_names():
                continue
            base_groups.setdefault(field.group, []).append(field)
        global_slots = {
            '基础': (0, 1, 1),
            '抓包': (1, 0, 1),
            'DNS与网关': (1, 1, 1),
            '重定向与黑名单': (2, 0, 2),
            'Linux': (3, 0, 2),
        }
        fallback_row = 4
        for group, fields in base_groups.items():
            frame = widgets.build_group_frame(
                self._global_inner, '[Diverter] · %s' % group, fields,
                getter('Diverter'), on_change('Diverter'), self._hint,
                self._registry, 'Diverter', columns=2,
                label_width=(20 if group == '重定向与黑名单'
                             else 16 if group == 'Linux' else 12))
            row, column, span = global_slots.get(
                group, (fallback_row, 0, 2))
            frame.grid(row=row, column=column, columnspan=span,
                       sticky='nsew', padx=3, pady=3)
            if group not in global_slots:
                fallback_row += 1

        egress_groups = {}
        for field in schema.DIVERTER_FIELDS:
            if field.group not in schema.egress_group_names():
                continue
            egress_groups.setdefault(field.group, []).append(field)
        egress_stack = ttk.Frame(self._egress_inner)
        egress_stack.grid(row=2, column=0, sticky='nsew', padx=3, pady=3)
        egress_stack.columnconfigure(0, weight=1)
        fallback_row = 3
        for group in schema.egress_group_names():
            fields = egress_groups.get(group, [])
            parent = egress_stack if group in ('私网接管', '公网IPv4放行') \
                else self._egress_inner
            frame = widgets.build_group_frame(
                parent, group, fields,
                getter('Diverter'), on_change('Diverter'), self._hint,
                self._registry, 'Diverter', columns=2,
                label_width=16 if group == '域名放行' else 12)
            if group == '域名放行':
                frame.grid(row=1, column=0, columnspan=2,
                           sticky='nsew', padx=3, pady=3)
            elif group in ('私网接管', '公网IPv4放行'):
                frame.pack(fill='x', pady=(0, 4))
            elif group == '进程重定向':
                frame.grid(row=2, column=1, sticky='nsew', padx=3, pady=3)
            else:
                frame.grid(row=fallback_row, column=0, columnspan=2,
                           sticky='nsew', padx=3, pady=3)
                fallback_row += 1
            for field in fields:
                self._egress_widgets[field.key] = \
                    self._registry[('Diverter', field.key.lower())]

    # ------------------------------------------------------------------
    # listeners tab
    # ------------------------------------------------------------------

    def _refresh_listener_list(self):
        self.listener_list.delete(0, 'end')
        names = [sec.name for sec in self.model.listener_sections()]
        for name in names:
            self.listener_list.insert('end', name)
        if self._selected_listener not in names:
            self._selected_listener = names[0] if names else None
        if self._selected_listener:
            index = names.index(self._selected_listener)
            self.listener_list.selection_clear(0, 'end')
            self.listener_list.selection_set(index)
            self.listener_list.activate(index)
        self._render_listener_panel()

    def _on_select_listener(self, _event=None):
        selection = self.listener_list.curselection()
        if not selection:
            return
        names = [sec.name for sec in self.model.listener_sections()]
        self._selected_listener = names[selection[0]]
        self._render_listener_panel()

    def _render_listener_panel(self):
        for child in self._listener_inner.winfo_children()[1:]:
            child.destroy()
        sec = (self.model.section(self._selected_listener)
               if self._selected_listener else None)
        if sec is None:
            self.expansion_var.set('')
            return
        try:
            expanded = self.model.expanded_listener_names(sec)
            preview = ('端口将展开为 %d 个实例: %s%s' %
                       (len(expanded), ', '.join(expanded[:5]),
                        ' …' if len(expanded) > 5 else '')) \
                if len(expanded) > 1 else ''
        except ValueError:
            preview = ''
        self.expansion_var.set(preview)

        listener_class = (sec.get('Listener') or '').strip()
        fields = schema.listener_fields(listener_class)
        known = {f.key.lower() for f in fields}
        self._registry = {
            k: v for k, v in self._registry.items()
            if k[0] not in ('FakeNet', 'Diverter')}
        self._building = True
        try:
            frame = widgets.build_group_frame(
                self._listener_inner, '[%s]' % sec.name, fields,
                lambda key: sec.get(key, '') or '',
                self._on_listener_field, self._hint,
                self._registry, sec.name)
            frame.pack(fill='x', pady=4)
            extras = [k for k in sec.keys() if k.lower() not in known]
            if extras:
                box = ttk.LabelFrame(self._listener_inner,
                                     text='额外键(schema 未收录,原样保留)')
                box.pack(fill='x', pady=4)
                for key in extras:
                    row = ttk.Frame(box)
                    row.pack(fill='x', padx=6, pady=1)
                    ttk.Label(row, text='%s:' % key).pack(side='left')
                    var = tk.StringVar(value=sec.get(key) or '')
                    var.trace_add('write', lambda *_a, k=key, v=var:
                                  self._on_extra_key(sec.name, k, v))
                    entry = ttk.Entry(row, textvariable=var)
                    entry.pack(side='left', fill='x', expand=True)
                    extra_hint = ('schema 未识别的扩展配置项;保存时原样写回,'
                                  '不转换也不校验')
                    widgets.attach_tooltip(
                        row, '%s\n%s' % (key, extra_hint),
                        self._hint, extra_hint)
                ttk.Label(box, style='Muted.TLabel',
                          text='提示:额外键保存时原样写回,不做任何转换')\
                    .pack(anchor='w', padx=6)
        finally:
            self._building = False

    def _on_listener_field(self, key, value):
        if self._building or not self._selected_listener:
            return
        sec = self.model.section(self._selected_listener)
        sec.set(key, value)
        self._mark_dirty()
        if key.lower() in ('listener', 'port'):
            self._render_listener_panel()
        self._schedule_validate()

    def _on_extra_key(self, section_name, key, var):
        sec = self.model.section(section_name)
        if sec is not None:
            sec.set(key, var.get())
            self._mark_dirty()
            self._schedule_validate()

    def _listener_add(self):
        name, listener_class = self._prompt_listener_section('新增监听器段',
                                                             'NewListener')
        if not name:
            return
        sec = self.model.ensure_section(name)
        sec.set('Enabled', 'True')
        sec.set('Port', '8080')
        sec.set('Protocol', 'TCP')
        sec.set('Hidden', 'False')
        if listener_class:
            sec.set('Listener', listener_class)
        self._selected_listener = name
        self._mark_dirty()
        self._refresh_listener_list()
        self._schedule_validate()

    def _prompt_listener_section(self, title, default):
        """Name prompt with the 10-class type dropdown (plan §5.4)."""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.transient(self.root)
        ttk.Label(dialog, text='段名:').grid(row=0, column=0, padx=8,
                                             pady=(8, 2), sticky='e')
        name_var = tk.StringVar(value=default)
        entry = ttk.Entry(dialog, textvariable=name_var, width=32)
        entry.grid(row=0, column=1, padx=8, pady=(8, 2))
        ttk.Label(dialog, text='监听器类型:').grid(row=1, column=0, padx=8,
                                                   pady=2, sticky='e')
        type_var = tk.StringVar(value='')
        type_box = ttk.Combobox(
            dialog, textvariable=type_var, state='readonly', width=30,
            values=['(匿名:仅重定向)'] + list(schema.LISTENER_CLASSES))
        type_box.current(0)
        type_box.grid(row=1, column=1, padx=8, pady=2)
        result = []

        def confirm():
            result.append((name_var.get().strip(),
                           '' if type_box.current() == 0
                           else type_var.get()))
            dialog.destroy()

        ttk.Button(dialog, text='确定', command=confirm)\
            .grid(row=2, column=0, columnspan=2, pady=8)
        entry.bind('<Return>', lambda _e: confirm())
        entry.focus_set()
        dialog.wait_window()
        if not result:
            return '', ''
        name, listener_class = result[0]
        if not name or name.lower() in ('fakenet', 'diverter'):
            if name:
                messagebox.showerror(title, '段名不能为 FakeNet/Diverter')
            return '', ''
        return name, listener_class

    def _listener_duplicate(self):
        if not self._selected_listener:
            return
        source = self.model.section(self._selected_listener)
        name = self._prompt_name('复制监听器段',
                                 '%s_copy' % self._selected_listener)
        if not name:
            return
        sec = self.model.ensure_section(name)
        for key, value in source.items():
            sec.set(key, value)
        self._selected_listener = name
        self._mark_dirty()
        self._refresh_listener_list()
        self._schedule_validate()

    def _listener_rename(self):
        if not self._selected_listener:
            return
        name = self._prompt_name('重命名监听器段', self._selected_listener)
        if not name or name == self._selected_listener:
            return
        try:
            self.model.rename_section(self._selected_listener, name)
        except ValueError as exc:
            messagebox.showerror('重命名', str(exc))
            return
        self._selected_listener = name
        self._mark_dirty()
        self._refresh_listener_list()
        self._schedule_validate()

    def _listener_delete(self):
        if not self._selected_listener:
            return
        if not messagebox.askyesno('删除监听器段',
                                   '确认删除 [%s]?' % self._selected_listener):
            return
        self.model.delete_section(self._selected_listener)
        self._selected_listener = None
        self._mark_dirty()
        self._refresh_listener_list()
        self._schedule_validate()

    def _prompt_name(self, title, default):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.transient(self.root)
        ttk.Label(dialog, text='段名:').grid(row=0, column=0, padx=8,
                                             pady=8)
        var = tk.StringVar(value=default)
        entry = ttk.Entry(dialog, textvariable=var, width=32)
        entry.grid(row=0, column=1, padx=8, pady=8)
        result = []

        def confirm():
            result.append(var.get().strip())
            dialog.destroy()

        ttk.Button(dialog, text='确定', command=confirm)\
            .grid(row=1, column=0, columnspan=2, pady=8)
        entry.bind('<Return>', lambda _e: confirm())
        entry.focus_set()
        dialog.wait_window()
        name = result[0] if result else ''
        if not name or name.lower() in ('fakenet', 'diverter'):
            if name:
                messagebox.showerror(title, '段名不能为 FakeNet/Diverter')
            return ''
        return name

    def autofix_topology(self):
        changes = validator.ensure_domain_allowlist_topology(self.model)
        self._mark_dirty()
        self._render_static_tabs()
        self._refresh_listener_list()
        self._schedule_validate()
        messagebox.showinfo(
            '一键补齐', '\n'.join(changes) if changes else '拓扑已完整,无需补齐')

    # ------------------------------------------------------------------
    # custom response tab
    # ------------------------------------------------------------------

    def _update_custom_content_state(self):
        if self.custom_model is None:
            self.custom_pane.pack_forget()
            if not self.custom_empty.winfo_manager():
                self.custom_empty.pack(fill='both', expand=True)
        else:
            self.custom_empty.pack_forget()
            if not self.custom_pane.winfo_manager():
                self.custom_pane.pack(fill='both', expand=True, padx=6,
                                      pady=(0, 6))

    def _custom_open(self):
        path = filedialog.askopenfilename(
            parent=self.root, filetypes=[('INI', '*.ini'), ('所有', '*.*')])
        if not path:
            return
        try:
            model = configmodel.ConfigModel.load(path)
        except Exception as exc:  # noqa: BLE001 - surfaced to the user
            messagebox.showerror('打开自定义响应文件', str(exc))
            return
        model.kind = 'custom'
        self.custom_model = model
        self._custom_selected = None
        self.custom_status.set(os.path.basename(path))
        self._update_custom_content_state()
        self._refresh_custom_list()

    def _custom_new(self):
        model = configmodel.ConfigModel()
        model.kind = 'custom'
        model.path = None
        self.custom_model = model
        self._custom_selected = None
        self.custom_status.set('未命名(新建)')
        self._update_custom_content_state()
        self._refresh_custom_list()

    def _custom_save(self):
        if self.custom_model is None:
            messagebox.showinfo('保存', '没有加载自定义响应文件')
            return
        path = self.custom_model.path
        if not path:
            path = filedialog.asksaveasfilename(
                parent=self.root, defaultextension='.ini',
                filetypes=[('INI', '*.ini')])
            if not path:
                return
            self.custom_model.path = os.path.abspath(path)
            self.custom_model.mtime = None
        try:
            self.custom_model.save()
        except configmodel.ExternalModifiedError:
            if messagebox.askyesno(
                    '保存', '文件已被外部修改,覆盖?'):
                self.custom_model.mtime = None
                self.custom_model.save()
            else:
                return
        self.custom_status.set(os.path.basename(self.custom_model.path))

    def _refresh_custom_list(self):
        self.custom_list.delete(0, 'end')
        if self.custom_model is None:
            self._update_custom_content_state()
            return
        self._update_custom_content_state()
        names = [sec.name for sec in self.custom_model.sections.values()]
        for name in names:
            self.custom_list.insert('end', name)
        if names:
            self.custom_list.selection_set(0)
            self._custom_selected = names[0]
        self._render_custom_panel()

    def _on_select_custom(self, _event=None):
        selection = self.custom_list.curselection()
        if not selection or self.custom_model is None:
            return
        names = [sec.name for sec in self.custom_model.sections.values()]
        self._custom_selected = names[selection[0]]
        self._render_custom_panel()

    def _render_custom_panel(self):
        for child in self._custom_inner.winfo_children():
            child.destroy()
        sec = (self.custom_model.section(self._custom_selected)
               if self.custom_model and self._custom_selected else None)
        if sec is None:
            return
        issues = validator.validate_custom(self.custom_model)
        mine = [i for i in issues if i.section == sec.name]
        if mine:
            text = '\n'.join('%s: %s' % (i.level, i.message) for i in mine)
            ttk.Label(self._custom_inner, text=text, foreground='#a00',
                      justify='left').pack(anchor='w')
        frame = widgets.build_group_frame(
            self._custom_inner, '[%s]' % sec.name,
            schema.CUSTOM_RESPONSE_FIELDS,
            lambda key: sec.get(key, '') or '',
            lambda key, value: self._on_custom_field(sec.name, key, value),
            self._hint)
        frame.pack(fill='x', pady=4)

    def _on_custom_field(self, section_name, key, value):
        sec = self.custom_model.section(section_name)
        if sec is not None:
            sec.set(key, value)
            self._render_custom_panel()

    def _custom_add(self):
        if self.custom_model is None:
            self._custom_new()
        name = self._prompt_name('新增自定义响应段', 'Example New')
        if not name:
            return
        self.custom_model.ensure_section(name)
        self._custom_selected = name
        self._refresh_custom_list()

    def _custom_delete(self):
        if self.custom_model is None or not self._custom_selected:
            return
        self.custom_model.delete_section(self._custom_selected)
        self._custom_selected = None
        self._refresh_custom_list()

    # ------------------------------------------------------------------
    # file operations
    # ------------------------------------------------------------------

    def new_config(self):
        self.model = configmodel.ConfigModel.new_config()
        self.model.path = None
        self._selected_listener = None
        self._rebuild_all()
        self._clear_dirty()

    def open_file(self):
        if not self._confirm_discard():
            return
        path = filedialog.askopenfilename(
            parent=self.root, filetypes=[('INI', '*.ini'), ('所有', '*.*')])
        if not path:
            return
        self._load_path(path)

    def restore_defaults(self):
        if self.model is None or not self.model.path:
            messagebox.showwarning(
                '恢复默认配置',
                '当前配置尚未绑定文件,请先保存配置或导入配置。',
                parent=self.root)
            return
        path = os.path.abspath(self.model.path)
        if not messagebox.askyesno(
                '恢复默认配置',
                '将使用默认配置覆盖当前文件:\n%s\n\n'
                '此操作无法撤销,是否继续?' % path,
                parent=self.root):
            return

        current = self.model
        replacement = configmodel.ConfigModel.new_config()
        replacement.path = path
        replacement.encoding = current.encoding
        replacement.bom = current.bom
        replacement.newline = current.newline
        replacement.mtime = None
        try:
            replacement.save(path)
        except OSError as exc:
            messagebox.showerror(
                '恢复默认配置', '覆盖配置文件失败:\n%s' % exc,
                parent=self.root)
            return

        self.model = replacement
        self._selected_listener = None
        self._rebuild_all()
        self._clear_dirty()

    def load_template(self, name):
        if not self._confirm_discard():
            return
        for directory in self._template_dirs():
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                self._load_path(path)
                return
        messagebox.showerror('模板载入', '模板不存在: %s' % name)

    def _load_path(self, path):
        try:
            model = configmodel.ConfigModel.load(path)
        except Exception as exc:  # noqa: BLE001 - surfaced to the user
            messagebox.showerror('打开', '无法解析配置文件:\n%s' % exc)
            return
        model.ensure_sections()
        self.model = model
        self._selected_listener = None
        self._rebuild_all()
        self._clear_dirty()

    def _rebuild_all(self):
        self._building = True
        try:
            self._render_static_tabs()
        finally:
            self._building = False
        self._refresh_listener_list()
        self._validate_now()

    def _confirm_discard(self):
        if not self.dirty:
            return True
        return messagebox.askyesno(
            '未保存的修改', '当前配置有未保存的修改,放弃并继续?')

    def save(self, as_else=False):
        if self.model is None:
            return
        path = self.model.path
        if as_else or not path:
            default_dir = self._default_save_dir()
            path = filedialog.asksaveasfilename(
                parent=self.root, defaultextension='.ini',
                initialdir=default_dir,
                initialfile='fakenet_config.ini',
                filetypes=[('INI', '*.ini')])
            if not path:
                return
            path = os.path.abspath(path)
            self.model.path = path
            self.model.mtime = None  # new target: don't compare mtime
        try:
            self.model.save(path)
        except configmodel.ExternalModifiedError:
            if messagebox.askyesno(
                    '保存', '文件在载入后被外部修改:\n%s\n\n覆盖保存?'
                    % self.model.path):
                self.model.mtime = None
                self.model.save(path)
            else:
                return
        except OSError as exc:
            messagebox.showerror('保存', '保存失败:\n%s' % exc)
            return
        self._clear_dirty()
        self._validate_now()

    def _default_save_dir(self):
        if getattr(sys, 'frozen', False):
            base = os.path.dirname(sys.executable)
        else:
            base = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))))
        candidates = [os.path.join(base, 'configs'), base]
        for directory in candidates:
            if os.path.isdir(directory):
                try:
                    probe = os.path.join(directory, '.fakenet-GUI-probe')
                    with open(probe, 'w') as handle:
                        handle.write('x')
                    os.remove(probe)
                    return directory
                except OSError:
                    continue
        return os.path.expanduser('~')

    # ------------------------------------------------------------------
    # launch pipeline (§5.5)
    # ------------------------------------------------------------------

    def launch(self):
        errors = [i for i in self._issues if i.level == validator.ERROR]
        if errors:
            messagebox.showwarning('启动', '存在 %d 个校验错误,请先修正'
                                   % len(errors))
            return
        if self.dirty or not self.model.path:
            choice = messagebox.askyesnocancel(
                '启动', '配置尚未保存。\n保存并继续启动?')
            if choice is None:
                return
            if choice:
                self.save()
                if self.dirty or not self.model.path:
                    return  # save was cancelled/failed
            else:
                return  # cannot launch without a file
        self.launch_button.state(['disabled'])
        threading.Thread(target=self._launch_gates, daemon=True).start()

    def _launch_gates(self):
        # Duplicate-instance gate (P3).
        if launcher.is_fakenet_running():
            self._ui(lambda: self._launch_abort(
                '检测到 fakenet.exe 已在运行。\n请先停止现有实例再启动'
                '(双 WinDivert 句柄属未定义行为)。'))
            return
        # VM gate (fail-closed, F1) - runs off the UI thread (P7).
        vm = launcher.query_vm_state()
        self.root.after(0, lambda: self._launch_vm_verdict(vm))

    def _launch_vm_verdict(self, vm):
        if vm.verdict == launcher.VERDICT_VM:
            self._launch_execute()
            return
        if vm.verdict == launcher.VERDICT_PHYSICAL:
            self._launch_abort(
                '本机识别为物理机,拒绝启动:\n%s\n\n请改用隔离 VM 运行。'
                % vm.detail)
            return
        self._launch_abort(
            'VM 检测不确定,按 fail-closed 拒绝启动:\n%s\n\n'
            '可改用 PowerShell 启动器,或修复 WMI/PowerShell 后重试。'
            % vm.detail)

    def _launch_abort(self, message):
        self.launch_button.state(['!disabled'])
        messagebox.showwarning('启动被拒绝', message)

    def _launch_execute(self):
        config_path = self.model.path
        if launcher.is_fakenet_running():
            self._launch_abort('检测到 fakenet.exe 已在运行。')
            return
        ok, reason = launcher.validate_config_path(config_path)
        if not ok:
            self._launch_abort('配置路径无效: %s' % reason)
            return
        if os.name != 'nt':
            messagebox.showinfo(
                '启动', 'Linux 下不提供直接启动。\n请手动运行:\n%s'
                % launcher.manual_command_hint(config_path))
            self.launch_button.state(['!disabled'])
            return
        settings = launcher.load_settings()
        exe, source, note = launcher.locate_fakenet_exe(settings)
        if exe is None:
            exe = filedialog.askopenfilename(
                parent=self.root, title='选择 fakenet.exe',
                filetypes=[('可执行', '*.exe')])
            if not exe:
                self._launch_abort('未指定 fakenet.exe,取消启动。')
                return
            exe = os.path.abspath(exe)
            settings['fakenet_exe'] = exe
            try:
                launcher.save_settings(settings)
            except OSError:
                pass
        if getattr(sys, 'frozen', False):
            target, params, directory = launcher.build_frozen_command(
                exe, config_path)
        else:
            target, params, directory = launcher.build_dev_command(
                config_path)
        launched, detail = launcher.launch_elevated(target, params,
                                                    directory)
        self.launch_button.state(['!disabled'])
        if not launched:
            messagebox.showwarning('启动', detail)
            return
        message = ('已启动 FakeNet-NG(配置: %s)。\n\n'
                   '后续对本配置的修改不影响运行中的实例'
                   '(fakenet 启动时一次性读取配置)。\n'
                   '请在新弹出的控制台窗口中操作,Ctrl+C 停止。'
                   % config_path)
        if note:
            message += '\n\n提示: %s' % note
        messagebox.showinfo('启动', message)

    def _ui(self, func):
        self.root.after(0, func)

    # ------------------------------------------------------------------
    # misc
    # ------------------------------------------------------------------

    def _jump_to_issue(self, _event=None):
        selection = self.panel.selection()
        if not selection:
            return
        values = self.panel.item(selection[0], 'values')
        location = values[1] if len(values) > 1 else ''
        if not location.startswith('['):
            return
        section = location[1:location.index(']')] if ']' in location else ''
        key = location.split(' ', 1)[1] if ' ' in location else ''
        widget = self._registry.get((section, key.lower()))
        if widget is None and section:
            for (sec_name, _k), candidate in self._registry.items():
                if sec_name == section:
                    widget = candidate
                    break
        if widget is None or not widget.winfo_exists():
            return
        tab_index = self._tab_of(widget)
        if tab_index is not None:
            self.notebook.select(tab_index)
        try:
            widget.input.focus_set()
        except tk.TclError:
            pass

    # -- validation panel copy / full-text support ---------------------------

    def _panel_popup(self, event):
        iid = self.panel.identify_row(event.y)
        if iid and iid not in self.panel.selection():
            self.panel.selection_set(iid)
        try:
            self._panel_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._panel_menu.grab_release()

    def _copy_selected_and_break(self, _event=None):
        self._copy_selected_issues()
        return 'break'

    @staticmethod
    def _row_text(values):
        # Treeview values hold the FULL message; copying never truncates.
        parts = [str(item) for item in (list(values) + ['', '', ''])[:3]]
        return '\t'.join(parts)

    def _copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._hint('已复制 %d 个字符到剪贴板' % len(text))

    def _copy_selected_issues(self):
        rows = [self.panel.item(iid)['values']
                for iid in self.panel.selection()]
        if not rows:
            self._hint('请先选中要复制的行(可按住 Ctrl 多选)')
            return
        self._copy_to_clipboard(
            '\n'.join(self._row_text(row) for row in rows))

    def _copy_all_issues(self):
        rows = [self.panel.item(iid)['values']
                for iid in self.panel.get_children()]
        if not rows:
            self._hint('当前没有校验结果')
            return
        self._copy_to_clipboard(
            '\n'.join(self._row_text(row) for row in rows))

    def _show_full_issue(self):
        rows = [self.panel.item(iid)['values']
                for iid in self.panel.selection()]
        if not rows:
            self._hint('请先选中要查看的行')
            return
        blocks = []
        for values in rows:
            level, location = str(values[0]), str(values[1])
            message = textwrap.fill(str(values[2]), width=76)
            blocks.append('%s  %s\n%s' % (level, location, message))
        messagebox.showinfo('完整消息', '\n\n'.join(blocks), parent=self.root)

    def _tab_of(self, widget):
        owner = widget.winfo_parent()
        while owner:
            for index in range(self.notebook.index('end')):
                if str(self.notebook.tabs()[index]) == owner:
                    return index
            try:
                owner = self.root.nametowidget(owner).winfo_parent()
            except tk.TclError:
                return None
        return None

    def _about(self):
        messagebox.showinfo(
            '关于', 'FakeNet-NG 配置工具\n\n可视化编辑 FakeNet-NG INI 配置并'
            '启动(带 VM/重复实例安全门)。\n方案: PLAN/2026.08.14 v1.10')

    def _on_close(self):
        if self.dirty and not messagebox.askyesno('退出',
                                                  '有未保存的修改,确定退出?'):
            return
        self.root.destroy()
