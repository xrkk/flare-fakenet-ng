# -*- coding: utf-8 -*-
"""fakenet-GUI main window (plan v0.2 §5.4).

Chinese UI.  Tabs: 全局 ([FakeNet] + [Diverter] base groups), 出站策略
(egress sub-groups with smart locking and topology auto-fix), 监听器
(section list + dynamic field panel), 自定义响应.  Bottom validation
panel with double-click jump-to-field; save + launch buttons.  The
launch pipeline runs VM/duplicate gates off the UI thread and is
fail-closed on inconclusive VM state.
"""

import os
import sys
import textwrap
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from fakenet.gui import configmodel, launcher, schema, validator, widgets

APP_TITLE = 'FakeNet-NG 配置工具'
TEMPLATE_EXCLUDE = ('sample_custom_response.ini',)
VALIDATE_DEBOUNCE_MS = 300


def scrollable(parent):
    """Canvas + scrollbar wrapper returning the inner frame.

    The wheel handler is re-pointed on Enter/Leave so several scrollable
    tabs don't fight over the global <MouseWheel> binding.
    """
    container = ttk.Frame(parent)
    canvas = tk.Canvas(container, highlightthickness=0)
    bar = ttk.Scrollbar(container, orient='vertical', command=canvas.yview)
    inner = ttk.Frame(canvas)
    inner.bind('<Configure>', lambda _e: canvas.configure(
        scrollregion=canvas.bbox('all')))
    window = canvas.create_window((0, 0), window=inner, anchor='nw')
    canvas.configure(yscrollcommand=bar.set)
    canvas.bind('<Configure>', lambda e: canvas.itemconfigure(
        window, width=e.width))
    canvas.pack(side='left', fill='both', expand=True)
    bar.pack(side='right', fill='y')

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

        root.title(APP_TITLE)
        root.geometry('980x700')
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
        top = ttk.Frame(self.root)
        top.pack(side='top', fill='x', padx=8, pady=(6, 0))
        self.summary_var = tk.StringVar(value='就绪')
        ttk.Label(top, textvariable=self.summary_var,
                  font=('', 10, 'bold')).pack(side='left')
        self.hint_var = tk.StringVar(value='')
        ttk.Label(top, textvariable=self.hint_var, foreground='#555')\
            .pack(side='left', padx=16)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(side='top', fill='both', expand=True,
                           padx=8, pady=6)
        self._build_global_tab()
        self._build_egress_tab()
        self._build_listeners_tab()
        self._build_custom_tab()

        bottom = ttk.Frame(self.root)
        bottom.pack(side='bottom', fill='x', padx=8, pady=(0, 8))
        self.launch_button = ttk.Button(bottom, text='▶ 启动 FakeNet-NG',
                                        command=self.launch)
        self.launch_button.pack(side='right')
        self.save_button = ttk.Button(bottom, text='保存配置',
                                      command=self.save)
        self.save_button.pack(side='right', padx=6)

        panel_header = ttk.Frame(bottom)
        panel_header.pack(side='bottom', fill='x')
        ttk.Label(panel_header,
                  text='校验结果(双击跳转 · 右键/Ctrl+C 复制 · 消息列可横向滚动)',
                  foreground='#555').pack(side='left')
        self.copy_all_button = ttk.Button(panel_header, text='复制全部',
                                          width=10,
                                          command=self._copy_all_issues)
        self.copy_all_button.pack(side='right')
        self.copy_selected_button = ttk.Button(panel_header, text='复制选中',
                                               width=10,
                                               command=self.
                                               _copy_selected_issues)
        self.copy_selected_button.pack(side='right', padx=4)

        panel_frame = ttk.Frame(bottom)
        panel_frame.pack(side='bottom', fill='x')
        self.panel = ttk.Treeview(panel_frame, height=8,
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
        self.panel.column('msg', width=680, minwidth=1600, stretch=True)
        xbar = ttk.Scrollbar(panel_frame, orient='horizontal',
                             command=self.panel.xview)
        ybar = ttk.Scrollbar(panel_frame, orient='vertical',
                             command=self.panel.yview)
        self.panel.configure(xscrollcommand=xbar.set,
                             yscrollcommand=ybar.set)
        ybar.pack(side='right', fill='y')
        self.panel.pack(side='top', fill='x')
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

    # ------------------------------------------------------------------
    # tab builders
    # ------------------------------------------------------------------

    def _build_global_tab(self):
        container, inner = scrollable(self.notebook)
        self.notebook.add(container, text='全局')
        self._global_inner = inner

    def _build_egress_tab(self):
        container, inner = scrollable(self.notebook)
        self.notebook.add(container, text='出站策略')
        ttk.Button(inner, text='一键补齐必需监听器(DomainEgressRelay + 2×DNS)',
                   command=self.autofix_topology).pack(anchor='w', pady=4)
        self._egress_inner = inner

    def _build_listeners_tab(self):
        pane = ttk.PanedWindow(self.notebook, orient='horizontal')
        self.notebook.add(pane, text='监听器')

        left = ttk.Frame(pane)
        pane.add(left, weight=1)
        self.listener_list = tk.Listbox(left, width=28, exportselection=False)
        self.listener_list.pack(fill='both', expand=True)
        self.listener_list.bind('<<ListboxSelect>>', self._on_select_listener)
        buttons = ttk.Frame(left)
        buttons.pack(fill='x')
        ttk.Button(buttons, text='新增', width=6,
                   command=self._listener_add).pack(side='left', padx=1)
        ttk.Button(buttons, text='复制', width=6,
                   command=self._listener_duplicate).pack(side='left',
                                                          padx=1)
        ttk.Button(buttons, text='重命名', width=8,
                   command=self._listener_rename).pack(side='left', padx=1)
        ttk.Button(buttons, text='删除', width=6,
                   command=self._listener_delete).pack(side='left', padx=1)

        right_container, right = scrollable(pane)
        pane.add(right_container, weight=3)
        self._listener_inner = right
        self.expansion_var = tk.StringVar(value='')
        ttk.Label(right, textvariable=self.expansion_var,
                  foreground='#555').pack(anchor='w')

    def _build_custom_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text='自定义响应')
        bar = ttk.Frame(tab)
        bar.pack(fill='x', pady=4)
        ttk.Button(bar, text='打开自定义响应文件…',
                   command=self._custom_open).pack(side='left')
        ttk.Button(bar, text='新建',
                   command=self._custom_new).pack(side='left', padx=4)
        ttk.Button(bar, text='保存', command=self._custom_save)\
            .pack(side='left')
        self.custom_status = tk.StringVar(value='未加载(由监听器的 Custom 键引用)')
        ttk.Label(bar, textvariable=self.custom_status,
                  foreground='#555').pack(side='left', padx=12)

        pane = ttk.PanedWindow(tab, orient='horizontal')
        pane.pack(fill='both', expand=True)
        left = ttk.Frame(pane)
        pane.add(left, weight=1)
        self.custom_list = tk.Listbox(left, width=28, exportselection=False)
        self.custom_list.pack(fill='both', expand=True)
        self.custom_list.bind('<<ListboxSelect>>', self._on_select_custom)
        addbox = ttk.Frame(left)
        addbox.pack(fill='x')
        ttk.Button(addbox, text='新增段', width=8,
                   command=self._custom_add).pack(side='left', padx=1)
        ttk.Button(addbox, text='删除段', width=8,
                   command=self._custom_delete).pack(side='left', padx=1)

        right_container, right = scrollable(pane)
        pane.add(right_container, weight=3)
        self._custom_inner = right
        self.custom_model = None
        self._custom_selected = None
        self._custom_registry = {}

    # ------------------------------------------------------------------
    # model wiring
    # ------------------------------------------------------------------

    def _hint(self, text):
        self.hint_var.set(text)

    def _mark_dirty(self):
        self.dirty = True
        name = os.path.basename(self.model.path) if self.model.path \
            else '未命名'
        self.root.title('%s* - %s' % (name, APP_TITLE))

    def _clear_dirty(self):
        self.dirty = False
        name = os.path.basename(self.model.path) if self.model.path \
            else '未命名'
        self.root.title('%s - %s' % (name, APP_TITLE))

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
        self.launch_button.state(['!disabled'] if not errors
                                 else ['disabled'])
        self.panel.delete(*self.panel.get_children())
        for issue in errors + warns:
            self.panel.insert('', 'end',
                              values=('错误' if issue.level == validator.ERROR
                                      else '警告',
                                      issue.location, issue.message))
        self._refresh_locks()

    def _refresh_locks(self):
        if self.model is None:
            return
        policy = (self.model.diverter().get('ExternalAccessPolicy') or
                  'Disabled').strip().lower() == 'domainallowlist'
        takeover = bool((self.model.diverter().get('ExternalTakeoverIPv4')
                         or '').strip())
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

    # ------------------------------------------------------------------
    # global / egress tabs render
    # ------------------------------------------------------------------

    def _render_static_tabs(self):
        for child in self._global_inner.winfo_children():
            child.destroy()
        for child in self._egress_inner.winfo_children()[1:]:
            child.destroy()
        self._egress_widgets = {}
        self._registry = {}

        def getter(section):
            return lambda key: (self.model.section(section).get(key, '') or
                                '')

        def on_change(section):
            def handler(key, value):
                if self._building:
                    return
                self.model.section(section).set(key, value)
                self._mark_dirty()
                self._schedule_validate()
            return handler

        fakenet_frame = widgets.build_group_frame(
            self._global_inner, '[FakeNet]', schema.FAKENET_FIELDS,
            getter('FakeNet'), on_change('FakeNet'), self._hint,
            self._registry, 'FakeNet')
        fakenet_frame.pack(fill='x', pady=4)

        base_groups = {}
        for field in schema.DIVERTER_FIELDS:
            if field.group in schema.egress_group_names():
                continue
            base_groups.setdefault(field.group, []).append(field)
        for group, fields in base_groups.items():
            frame = widgets.build_group_frame(
                self._global_inner, '[Diverter] · %s' % group, fields,
                getter('Diverter'), on_change('Diverter'), self._hint,
                self._registry, 'Diverter')
            frame.pack(fill='x', pady=4)

        egress_groups = {}
        for field in schema.DIVERTER_FIELDS:
            if field.group not in schema.egress_group_names():
                continue
            egress_groups.setdefault(field.group, []).append(field)
        for group in schema.egress_group_names():
            fields = egress_groups.get(group, [])
            frame = widgets.build_group_frame(
                self._egress_inner, group, fields,
                getter('Diverter'), on_change('Diverter'), self._hint,
                self._registry, 'Diverter')
            frame.pack(fill='x', pady=4)
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
                    ttk.Entry(row, textvariable=var).pack(
                        side='left', fill='x', expand=True)
                ttk.Label(box, foreground='#777',
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
        self._refresh_custom_list()

    def _custom_new(self):
        model = configmodel.ConfigModel()
        model.kind = 'custom'
        model.path = None
        self.custom_model = model
        self._custom_selected = None
        self.custom_status.set('未命名(新建)')
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
            return
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
            '启动(带 VM/重复实例安全门)。\n方案: PLAN/2026.08.14 v0.2')

    def _on_close(self):
        if self.dirty and not messagebox.askyesno('退出',
                                                  '有未保存的修改,确定退出?'):
            return
        self.root.destroy()
