# -*- coding: utf-8 -*-
"""fakenet-GUI main window (plan v1.13 §5.4/§12.17).

Chinese, native tkinter/ttk UI.  Five task-oriented tabs keep configuration,
validation, launch lifecycle and the current FakeNet log in one small tool.
Validation details live in a separate native window so they never consume the
main editor's vertical space.
"""

import codecs
import hashlib
import logging
import os
import queue
import sys
import textwrap
import threading
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox

from fakenet.gui import (configmodel, launcher, schema, startup_logging,
                         validator, widgets)

APP_TITLE = 'FakeNet-NG 配置工具'
TEMPLATE_EXCLUDE = ('sample_custom_response.ini',)
VALIDATE_DEBOUNCE_MS = 300
LOG_POLL_MS = 250
LOG_LARGE_BYTES = 25 * 1024 * 1024

# Window metrics follow the v1.15 50% readability scale (plan §12.19): the
# 980x700 / 900x420 v1.13 defaults enlarged with the font system.
MAIN_WINDOW_SIZE = '1470x1050'
MAIN_WINDOW_MIN_SIZE = (1350, 960)
VALIDATION_WINDOW_SIZE = '1350x630'
VALIDATION_WINDOW_MIN_SIZE = (1020, 450)

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
                    family='Microsoft YaHei UI', size=widgets.scaled(9))
            except tk.TclError:
                pass
    root.configure(background=COLOR_BG)
    style = ttk.Style(root)
    style.configure('TNotebook.Tab', padding=(18, 8))
    style.configure('TLabelframe', padding=(6, 6))
    style.configure('Muted.TLabel', foreground=COLOR_MUTED)
    style.configure('Locked.TLabel', foreground=COLOR_MUTED)
    style.configure('Success.TLabel', foreground=COLOR_SUCCESS,
                    font=('', widgets.scaled(9), 'bold'))
    style.configure('Warning.TLabel', foreground=COLOR_WARNING,
                    font=('', widgets.scaled(9), 'bold'))
    style.configure('Error.TLabel', foreground=COLOR_ERROR,
                    font=('', widgets.scaled(9), 'bold'))
    style.configure('InlineError.TLabel', foreground=COLOR_ERROR,
                    font=('', widgets.scaled(8)))
    style.configure('SectionTitle.TLabel', foreground='#1F2937',
                    font=('', widgets.scaled(10), 'bold'))
    style.configure('Primary.TButton', padding=(18, 9),
                    foreground=COLOR_PRIMARY,
                    font=('', widgets.scaled(9), 'bold'))
    style.configure('Action.TButton', padding=(15, 8))
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
        self._validation_window = None
        self.panel = None
        self._panel_menu = None
        self._tabs_built = set()
        self._running = False
        self._fakenet_process_handle = None
        self._fakenet_log_path = None
        self._log_offset = 0
        self._log_job = None
        self._hash_generation = 0
        self._hash_pending = False
        self._hash_issue = None
        self._ui_queue = queue.Queue()
        self._ui_job = None
        self._action_buttons = []
        self.custom_model = None
        self._custom_selected = None
        self._custom_registry = {}
        self.logger = logging.getLogger('fakenet.GUI')

        root.title(APP_TITLE)
        root.geometry(MAIN_WINDOW_SIZE)
        root.minsize(*MAIN_WINDOW_MIN_SIZE)
        configure_styles(root)
        self._build_menu()
        self._build_layout()
        self._ui_job = root.after(25, self._drain_ui_queue)
        self.new_config()
        root.protocol('WM_DELETE_WINDOW', self._on_close)
        root.bind('<Destroy>', self._on_root_destroy, add='+')

    # ------------------------------------------------------------------
    # menus / layout
    # ------------------------------------------------------------------

    def _build_menu(self):
        menubar = tk.Menu(self.root)
        self.file_menu = tk.Menu(menubar, tearoff=0)
        self.file_menu.add_command(label='新建', command=self.new_config)
        self.file_menu.add_command(label='打开…', command=self.open_file)
        self.file_menu.add_command(label='保存', command=self.save,
                                   accelerator='Ctrl+S')
        self.file_menu.add_command(label='另存为…', command=lambda:
                                   self.save(as_else=True))
        self.file_menu.add_separator()
        self.file_menu.add_command(label='退出', command=self._on_close)
        menubar.add_cascade(label='文件', menu=self.file_menu)

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
        ttk.Label(top, text='配置提示', style='SectionTitle.TLabel').pack(
            side='left')
        self.hint_var = tk.StringVar(value='')
        ttk.Label(top, textvariable=self.hint_var, style='Muted.TLabel')\
            .pack(side='left', padx=16)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=1, column=0, sticky='nsew', padx=8,
                           pady=(4, 4))
        self._tab_frames = []
        for title in ('基础配置', '出站策略', '监听器', '自定义响应',
                      '实时日志'):
            tab = ttk.Frame(self.notebook)
            self.notebook.add(tab, text=title)
            self._tab_frames.append(tab)
        self.notebook.bind('<<NotebookTabChanged>>', self._on_tab_changed)
        self._ensure_tab(0)

        validation = ttk.Frame(self.root, padding=(10, 2, 10, 4))
        validation.grid(row=2, column=0, sticky='ew')
        self.validation_summary_var = tk.StringVar(value='✓ 校验通过')
        self.validation_summary_label = ttk.Label(
            validation, textvariable=self.validation_summary_var,
            style='Success.TLabel', takefocus=True)
        self.validation_summary_label.pack(side='left')
        self.validation_summary_label.bind(
            '<Button-1>', self._open_validation_from_event)
        self.validation_summary_label.bind(
            '<Return>', self._open_validation_from_event)
        self.validation_summary_label.bind(
            '<space>', self._open_validation_from_event)
        ttk.Label(validation, text='有问题时点击查看完整详情',
                  style='Muted.TLabel').pack(side='left', padx=(10, 0))
        # Compatibility alias used by callers/tests that inspect the summary.
        self.summary_var = self.validation_summary_var
        self.summary_label = self.validation_summary_label

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
        self._action_buttons = [self.import_button, self.restore_button,
                                self.save_button]
        widgets.attach_tooltip(
            self.import_button,
            '导入配置\n打开并编辑现有 INI;保存配置时将写回该文件。',
            self._hint, '打开并绑定现有 INI;保存时写回原文件')
        widgets.attach_tooltip(
            self.restore_button,
            '恢复默认配置\n确认后使用安全默认配置立即覆盖当前绑定的 INI 文件。',
            self._hint, '确认后立即覆盖当前绑定文件')

    # ------------------------------------------------------------------
    # tab builders
    # ------------------------------------------------------------------

    def _on_tab_changed(self, _event=None):
        try:
            index = self.notebook.index(self.notebook.select())
        except tk.TclError:
            return
        self._ensure_tab(index)

    def _ensure_tab(self, index):
        if index in self._tabs_built:
            return
        builders = (self._build_global_tab, self._build_egress_tab,
                    self._build_listeners_tab, self._build_custom_tab,
                    self._build_log_tab)
        builders[index]()
        self._tabs_built.add(index)
        if self.model is not None:
            self._building = True
            try:
                if index == 0:
                    self._render_global_tab()
                elif index == 1:
                    self._render_egress_tab()
                elif index == 2:
                    self._refresh_listener_list()
                elif index == 3:
                    self._update_custom_content_state()
            finally:
                self._building = False
            self._apply_inline_errors([
                issue for issue in self._issues
                if issue.level == validator.ERROR])

    def _build_global_tab(self):
        container, inner = scrollable(self._tab_frames[0])
        container.pack(fill='both', expand=True)
        self._global_scroll = container
        self._global_inner = inner

    def _build_egress_tab(self):
        container, inner = scrollable(self._tab_frames[1])
        container.pack(fill='both', expand=True)
        self._egress_scroll = container
        inner.columnconfigure(0, weight=1, uniform='egress-group')
        inner.columnconfigure(1, weight=1, uniform='egress-group')
        self._egress_inner = inner

    def _build_listeners_tab(self):
        pane = ttk.PanedWindow(self._tab_frames[2], orient='horizontal')
        pane.pack(fill='both', expand=True)

        left = ttk.Frame(pane, padding=(2, 0, 4, 0))
        pane.add(left, weight=1)
        user_box = ttk.LabelFrame(left, text='用户监听器')
        user_box.pack(fill='both', expand=True)
        self.listener_list = tk.Listbox(user_box, width=24,
                                        exportselection=False)
        self.listener_list.pack(fill='both', expand=True, padx=3, pady=3)
        self.listener_list.bind('<<ListboxSelect>>', self._on_select_listener)
        buttons = ttk.Frame(user_box)
        buttons.pack(fill='x', padx=2, pady=(0, 3))
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

        system_box = ttk.LabelFrame(left, text='系统自动管理')
        system_box.pack(fill='x', pady=(6, 0))
        self.system_listener_list = tk.Listbox(
            system_box, width=24, height=5, exportselection=False)
        self.system_listener_list.pack(fill='x', padx=3, pady=3)
        self.system_listener_list.bind(
            '<<ListboxSelect>>', self._on_select_system_listener)
        self.regenerate_system_button = ttk.Button(
            system_box, text='重新生成必需监听器',
            command=self._regenerate_system_listeners)
        self.regenerate_system_button.pack(fill='x', padx=3, pady=(0, 4))
        widgets.attach_tooltip(
            self.regenerate_system_button,
            '重新生成必需监听器\n按当前出站策略重新检查并补齐 DNS UDP/TCP 53 与 DomainEgressRelay;不会批量删除普通 DNS 监听器。',
            self._hint, '重新检查并补齐出站策略必需监听器')

        right_container, right = scrollable(pane)
        pane.add(right_container, weight=5)
        self._listener_inner = right
        self.expansion_var = tk.StringVar(value='')
        ttk.Label(right, textvariable=self.expansion_var,
                  style='Muted.TLabel').pack(anchor='w')

    def _build_custom_tab(self):
        tab = self._tab_frames[3]
        bar = ttk.Frame(tab)
        bar.pack(fill='x', padx=6, pady=6)
        self.custom_action_buttons = []
        for text, command, padding in (
                ('打开响应文件…', self._custom_open, 0),
                ('新建响应文件', self._custom_new, 4),
                ('保存响应文件', self._custom_save, 0)):
            button = ttk.Button(bar, text=text, style='Action.TButton',
                                command=command)
            button.pack(side='left', padx=(padding, 0))
            self.custom_action_buttons.append(button)
        self.custom_status = tk.StringVar(value='未加载(由监听器的 Custom 键引用)')
        ttk.Label(bar, textvariable=self.custom_status,
                  style='Muted.TLabel').pack(side='left', padx=12)

        self.custom_empty = ttk.Frame(tab, padding=(24, 70))
        self.custom_empty_title_var = tk.StringVar(
            value='尚未加载自定义响应文件')
        self.custom_empty_help_var = tk.StringVar(
            value='自定义响应文件由监听器中的 Custom 字段引用。\n'
                  '请打开已有 INI，或新建一个响应文件后添加配置段。')
        ttk.Label(self.custom_empty, textvariable=self.custom_empty_title_var,
                  font=('', widgets.scaled(11), 'bold')).pack()
        ttk.Label(self.custom_empty, textvariable=self.custom_empty_help_var,
                  justify='center', style='Muted.TLabel').pack(pady=(10, 8))
        self.custom_empty_add_button = ttk.Button(
            self.custom_empty, text='新增配置段…', command=self._custom_add)

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
        self._update_custom_content_state()

    def _build_log_tab(self):
        tab = self._tab_frames[4]
        toolbar = ttk.Frame(tab, padding=(8, 7, 8, 5))
        toolbar.pack(fill='x')
        ttk.Label(toolbar, text='当前日志:', style='SectionTitle.TLabel')\
            .pack(side='left')
        self.log_path_var = tk.StringVar(value='尚未启动 FakeNet-NG')
        ttk.Label(toolbar, textvariable=self.log_path_var,
                  style='Muted.TLabel').pack(side='left', fill='x',
                                             expand=True, padx=(8, 8))
        self.log_pause_var = tk.BooleanVar(value=False)
        self.log_pause_button = ttk.Checkbutton(
            toolbar, text='暂停自动滚动', variable=self.log_pause_var)
        self.log_pause_button.pack(side='right')
        self.open_log_dir_button = ttk.Button(
            toolbar, text='打开日志目录', command=self._open_log_directory)
        self.open_log_dir_button.pack(side='right', padx=(0, 8))
        self.open_log_dir_button.state(['disabled'])
        text_frame = ttk.Frame(tab, padding=(8, 0, 8, 8))
        text_frame.pack(fill='both', expand=True)
        self.log_text = tk.Text(
            text_frame, wrap='none', state='disabled', undo=False,
            font=('Consolas', widgets.scaled(9)), background='#FFFFFF',
            foreground='#1F2937')
        ybar = ttk.Scrollbar(text_frame, orient='vertical',
                             command=self.log_text.yview)
        xbar = ttk.Scrollbar(text_frame, orient='horizontal',
                             command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=ybar.set,
                                xscrollcommand=xbar.set)
        self.log_text.grid(row=0, column=0, sticky='nsew')
        ybar.grid(row=0, column=1, sticky='ns')
        xbar.grid(row=1, column=0, sticky='ew')
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)
        self.log_state_var = tk.StringVar(value='启动后将在此显示完整实时日志。')
        ttk.Label(tab, textvariable=self.log_state_var,
                  style='Muted.TLabel').pack(anchor='w', padx=10, pady=(0, 6))

    # ------------------------------------------------------------------
    # model wiring
    # ------------------------------------------------------------------

    def _hint(self, text):
        self.hint_var.set(text)

    def _open_validation_from_event(self, _event=None):
        if self._issues:
            self.open_validation_window()
        return 'break'

    def open_validation_window(self):
        """Show the complete validation result outside the main workspace."""
        if self._validation_window is not None:
            try:
                self._validation_window.deiconify()
                self._validation_window.lift()
                self._validation_window.focus_force()
                return
            except tk.TclError:
                self._validation_window = None
                self.panel = None
        window = tk.Toplevel(self.root)
        window.title('配置校验详情')
        window.transient(self.root)
        window.geometry(VALIDATION_WINDOW_SIZE)
        window.minsize(*VALIDATION_WINDOW_MIN_SIZE)
        self._validation_window = window
        header = ttk.Frame(window, padding=(8, 8, 8, 5))
        header.pack(fill='x')
        self.validation_window_summary_label = ttk.Label(
            header, textvariable=self.validation_summary_var,
            style=self.validation_summary_label.cget('style'))
        self.validation_window_summary_label.pack(side='left')
        ttk.Label(header, text='双击跳转 · 右键/Ctrl+C 复制',
                  style='Muted.TLabel').pack(side='left', padx=(10, 0))
        ttk.Button(header, text='复制全部', width=9,
                   command=self._copy_all_issues).pack(side='right')
        ttk.Button(header, text='复制选中', width=9,
                   command=self._copy_selected_issues).pack(
                       side='right', padx=(0, 5))
        body = ttk.Frame(window, padding=(8, 0, 8, 8))
        body.pack(fill='both', expand=True)
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        self.panel = ttk.Treeview(
            body, columns=('level', 'loc', 'msg'), show='headings',
            selectmode='extended')
        self.panel.heading('level', text='级别')
        self.panel.heading('loc', text='位置')
        self.panel.heading('msg', text='消息')
        self.panel.column('level', width=58, minwidth=58, stretch=False)
        self.panel.column('loc', width=250, minwidth=210, stretch=False)
        self.panel.column('msg', width=1100, minwidth=620, stretch=False)
        xbar = ttk.Scrollbar(body, orient='horizontal',
                             command=self.panel.xview)
        ybar = ttk.Scrollbar(body, orient='vertical',
                             command=self.panel.yview)
        self.panel.configure(xscrollcommand=xbar.set,
                             yscrollcommand=ybar.set)
        self.panel.grid(row=0, column=0, sticky='nsew')
        ybar.grid(row=0, column=1, sticky='ns')
        xbar.grid(row=1, column=0, sticky='ew')
        self.panel.bind('<Double-1>', self._jump_to_issue)
        self.panel.bind('<Button-3>', self._panel_popup)
        self.panel.bind('<Control-c>', self._copy_selected_and_break)
        self._panel_menu = tk.Menu(window, tearoff=0)
        self._panel_menu.add_command(label='复制选中行 (Ctrl+C)',
                                     command=self._copy_selected_issues)
        self._panel_menu.add_command(label='复制全部',
                                     command=self._copy_all_issues)
        self._panel_menu.add_separator()
        self._panel_menu.add_command(label='查看完整消息…',
                                     command=self._show_full_issue)
        window.protocol('WM_DELETE_WINDOW', self._close_validation_window)
        self._populate_validation_panel()
        if self.panel.get_children():
            first = self.panel.get_children()[0]
            self.panel.selection_set(first)
            self.panel.focus(first)
        self.panel.focus_set()

    def _close_validation_window(self):
        if self._validation_window is not None:
            try:
                self._validation_window.destroy()
            except tk.TclError:
                pass
        self._validation_window = None
        self.validation_window_summary_label = None
        self.panel = None
        self._panel_menu = None

    def _populate_validation_panel(self):
        if self.panel is None:
            return
        try:
            self.panel.delete(*self.panel.get_children())
            for issue in self._issues:
                self.panel.insert(
                    '', 'end', values=(
                        '错误' if issue.level == validator.ERROR else '警告',
                        issue.location, issue.message))
        except tk.TclError:
            self.panel = None

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
        if self._hash_issue is not None:
            self._issues.append(self._hash_issue)
        errors = [i for i in self._issues if i.level == validator.ERROR]
        warns = [i for i in self._issues if i.level == validator.WARNING]
        if errors:
            style = 'Error.TLabel'
            detail = '✕ %d 个错误 / %d 个警告' % (len(errors), len(warns))
        elif warns:
            style = 'Warning.TLabel'
            detail = '⚠ 0 个错误 / %d 个警告' % len(warns)
        else:
            style = 'Success.TLabel'
            detail = '✓ 校验通过'
        self.validation_summary_label.configure(style=style)
        if getattr(self, 'validation_window_summary_label', None) is not None:
            self.validation_window_summary_label.configure(style=style)
        self.validation_summary_var.set(detail)
        self.validation_summary_label.configure(
            cursor='hand2' if self._issues else '')
        self._populate_validation_panel()
        self._apply_inline_errors(errors)
        self._refresh_locks()
        self._update_action_states()

    def _apply_inline_errors(self, errors):
        for widget in list(self._registry.values()):
            if hasattr(widget, 'set_error'):
                widget.set_error('')
        shown = set()
        for issue in errors:
            identity = (issue.section, issue.key.lower())
            widget = self._registry.get(identity)
            if widget is None or identity in shown:
                continue
            shown.add(identity)
            message = issue.message
            if len(message) > 140:
                message = message[:137] + '…'
            if hasattr(widget, 'set_error'):
                widget.set_error(message)

    def _update_action_states(self):
        errors = any(i.level == validator.ERROR for i in self._issues)
        launch_disabled = errors or self._running or self._hash_pending
        self.launch_button.state(
            ['disabled'] if launch_disabled else ['!disabled'])
        state = ['disabled'] if self._running else ['!disabled']
        for button in self._action_buttons:
            button.state(state)
        for index in range(4):
            try:
                self.file_menu.entryconfigure(
                    index, state='disabled' if self._running else 'normal')
            except tk.TclError:
                pass
        end = self.template_menu.index('end')
        if end is not None:
            for index in range(end + 1):
                try:
                    self.template_menu.entryconfigure(
                        index, state='disabled' if self._running else 'normal')
                except tk.TclError:
                    pass
        for button in getattr(self, 'custom_action_buttons', ()):
            button.state(state)
        if hasattr(self, 'custom_empty_add_button'):
            self.custom_empty_add_button.state(state)
        self._update_listener_action_states()

    def _refresh_locks(self):
        if self.model is None:
            return
        diverter = self.model.diverter()
        policy = (diverter.get('ExternalAccessPolicy') or
                  schema.EGRESS_POLICY_DISABLED).strip().lower() == \
            schema.EGRESS_POLICY_ENABLED.lower()
        takeover = 'ExternalTakeoverIPv4' in diverter
        process_enabled = (diverter.get(
            'ExternalProcessRedirectEnabled') or 'No').strip().lower() == 'yes'
        public_enabled = 'ExternalAllowedIPv4Rules' in diverter
        for key, widget in self._egress_widgets.items():
            field = schema.diverter_field(key)
            if field is None:
                continue
            if field.key == 'ExternalAccessPolicy':
                widget.set_locked(False)
            elif field.key == 'ExternalProcessRedirectImageSHA256':
                widget.set_locked(True, reason='自动计算')
            elif field.lock:
                widget.set_locked(True)  # implementation details are read-only
            elif field.cond_lock == schema.COND_TAKEOVER_DOMAINS:
                if not policy:
                    widget.set_locked(True, reason='出站策略未启用')
                elif takeover:
                    widget.set_locked(True, forced_value='api.deepseek.com')
                else:
                    widget.set_locked(False)
            elif field.cond_lock == schema.COND_TAKEOVER_ACTION:
                if not policy:
                    widget.set_locked(True, reason='出站策略未启用')
                elif takeover:
                    widget.set_locked(True, forced_value='Divert')
                else:
                    widget.set_locked(False)
            else:
                locked = not policy
                reason = '出站策略未启用'
                if not locked and field.group == '私网接管' and not takeover:
                    locked, reason = True, '未启用私网接管'
                elif not locked and field.key == 'ExternalAllowedIPv4Rules' \
                        and not public_enabled:
                    locked, reason = True, '未启用公网 IPv4 直连'
                elif not locked and field.group == '进程重定向' and \
                        field.key != 'ExternalProcessRedirectEnabled' and \
                        not process_enabled:
                    locked, reason = True, '未启用进程重定向'
                widget.set_locked(locked, reason=reason)
        if hasattr(self, 'takeover_check'):
            self.takeover_check.state(
                ['disabled'] if (not policy or self._running)
                else ['!disabled'])
        if hasattr(self, 'public_ipv4_check'):
            self.public_ipv4_check.state(
                ['disabled'] if (not policy or self._running)
                else ['!disabled'])
        if self._running:
            for widget in list(self._registry.values()):
                if hasattr(widget, 'set_locked'):
                    widget.set_locked(True, reason='FakeNet 运行中')

    def _sync_active_egress_policy(self):
        """Materialize enforced values and topology for an active policy."""
        diverter = self.model.diverter()
        policy = (diverter.get('ExternalAccessPolicy') or
                  schema.EGRESS_POLICY_DISABLED).strip().lower() == \
            schema.EGRESS_POLICY_ENABLED.lower()
        if not policy:
            return []
        changes = []
        values = dict(schema.LOCKED_FIELD_VALUES)
        if 'ExternalTakeoverIPv4' in diverter:
            values.update({
                'ExternalAllowedDomains': 'api.deepseek.com',
                'ExternalNonAllowedAction': 'Divert',
            })
        for key, value in values.items():
            if diverter.get(key) != value:
                diverter.set(key, value)
                changes.append('[Diverter] %s 已同步为 %s' % (key, value))
            widget = self._egress_widgets.get(key)
            if widget is not None and widget.get() != value:
                widget.set(value)
        changes.extend(validator.ensure_domain_allowlist_topology(self.model))
        if changes:
            self._hint('已自动补齐出站策略必需配置')
        return changes

    # ------------------------------------------------------------------
    # global / egress tabs render
    # ------------------------------------------------------------------

    def _field_getter(self, section):
        return lambda key: (self.model.section(section).get(key, '') or '')

    def _on_static_field(self, section, key, value):
        if self._building or self._running:
            return
        holder = self.model.section(section)
        old = holder.get(key, '') or ''
        if old == value:
            return
        holder.set(key, value)
        field = schema.diverter_field(key) if section == 'Diverter' else None
        if key == 'ExternalProcessRedirectImagePath':
            self._start_process_hash(value, update_model=True)
        elif key == 'ExternalProcessRedirectEnabled':
            if value.strip().lower() == 'yes':
                self._start_process_hash(
                    holder.get('ExternalProcessRedirectImagePath') or '',
                    update_model=False)
            else:
                self._hash_generation += 1
                self._hash_pending = False
                self._hash_issue = None
        if field and field.group in schema.egress_group_names():
            changes = self._sync_active_egress_policy()
            if changes and 2 in self._tabs_built:
                self._refresh_listener_list()
            self._refresh_locks()
        self._mark_dirty()
        self._schedule_validate()

    def _start_process_hash(self, path, update_model=False):
        """Hash/verify the selected PE off the Tk thread.

        A user path change clears and replaces the derived digest.  Loading a
        file verifies the persisted digest without silently rewriting it.
        """
        self._hash_generation += 1
        generation = self._hash_generation
        self._hash_issue = None
        path = (path or '').strip()
        diverter = self.model.diverter() if self.model is not None else None
        if update_model and diverter is not None:
            diverter.set('ExternalProcessRedirectImageSHA256', '')
            sha_widget = self._egress_widgets.get(
                'ExternalProcessRedirectImageSHA256')
            if sha_widget is not None:
                sha_widget.set('')
        if not path or not os.path.isfile(path):
            self._hash_pending = False
            self._schedule_validate()
            return
        self._hash_pending = True
        self._update_action_states()

        def worker():
            digest = hashlib.sha256()
            error = None
            try:
                with open(path, 'rb') as handle:
                    while True:
                        chunk = handle.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                value = digest.hexdigest()
            except OSError as exc:
                value = ''
                error = str(exc)
            self._ui(lambda: self._finish_process_hash(
                generation, path, value, error, update_model))

        threading.Thread(target=worker, name='ProcessImageSHA256',
                         daemon=True).start()

    def _finish_process_hash(self, generation, path, digest, error,
                             update_model):
        if generation != self._hash_generation or self.model is None:
            return
        diverter = self.model.diverter()
        current_path = (diverter.get(
            'ExternalProcessRedirectImagePath') or '').strip()
        if current_path != path:
            return
        self._hash_pending = False
        if error:
            self._hash_issue = validator.Issue(
                validator.ERROR, 'Diverter',
                'ExternalProcessRedirectImagePath',
                '读取目标程序失败: %s' % error)
        elif update_model:
            diverter.set('ExternalProcessRedirectImageSHA256', digest)
            widget = self._egress_widgets.get(
                'ExternalProcessRedirectImageSHA256')
            if widget is not None:
                widget.set(digest)
            self._hash_issue = None
            self._hint('已自动计算目标程序 SHA-256')
        else:
            configured = (diverter.get(
                'ExternalProcessRedirectImageSHA256') or '').strip().lower()
            if configured and configured != digest:
                self._hash_issue = validator.Issue(
                    validator.ERROR, 'Diverter',
                    'ExternalProcessRedirectImageSHA256',
                    '配置中的 SHA-256 与当前目标程序不一致;请重新选择目标程序')
        self._validate_now()

    def _render_global_tab(self):
        if 0 not in self._tabs_built:
            return
        for child in self._global_inner.winfo_children():
            child.destroy()
        global_keys = {field.key.lower() for field in schema.FAKENET_FIELDS}
        global_diverter_keys = {
            field.key.lower() for field in schema.DIVERTER_FIELDS
            if field.group not in schema.egress_group_names()}
        self._registry = {
            identity: widget for identity, widget in self._registry.items()
            if not (identity[0] == 'FakeNet' and
                    identity[1] in global_keys) and
            not (identity[0] == 'Diverter' and
                 identity[1] in global_diverter_keys)}
        for column in range(2):
            self._global_inner.columnconfigure(
                column, weight=1, uniform='global-group')

        fakenet_frame = widgets.build_group_frame(
            self._global_inner, '[FakeNet]', schema.FAKENET_FIELDS,
            self._field_getter('FakeNet'),
            lambda key, value: self._on_static_field('FakeNet', key, value),
            self._hint,
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
                self._field_getter('Diverter'),
                lambda key, value: self._on_static_field(
                    'Diverter', key, value), self._hint,
                self._registry, 'Diverter', columns=2,
                label_width=(20 if group == '重定向与黑名单'
                             else 16 if group == 'Linux' else 12))
            row, column, span = global_slots.get(
                group, (fallback_row, 0, 2))
            frame.grid(row=row, column=column, columnspan=span,
                       sticky='nsew', padx=3, pady=3)
            if group not in global_slots:
                fallback_row += 1

    def _render_egress_tab(self):
        if 1 not in self._tabs_built:
            return
        for child in self._egress_inner.winfo_children():
            child.destroy()
        egress_keys = {
            field.key.lower() for field in schema.DIVERTER_FIELDS
            if field.group in schema.egress_group_names()}
        self._registry = {
            identity: widget for identity, widget in self._registry.items()
            if not (identity[0] == 'Diverter' and
                    identity[1] in egress_keys)}
        self._egress_widgets = {}
        getter = self._field_getter('Diverter')
        changed = lambda key, value: self._on_static_field(
            'Diverter', key, value)
        field_by_key = {field.key: field for field in schema.DIVERTER_FIELDS}

        base = ttk.LabelFrame(
            self._egress_inner, text='出站控制与真实域名访问')
        base.grid(row=0, column=0, columnspan=2, sticky='nsew',
                  padx=3, pady=3)
        base.columnconfigure(0, weight=1)
        base.columnconfigure(1, weight=1)
        base_fields = [field_by_key[key] for key in (
            'ExternalAccessPolicy', 'ExternalDnsServer',
            'ExternalDnsTimeout', 'ExternalRelayPort',
            'ExternalNonAllowedAction')]
        base_values = widgets.build_group_frame(
            base, '连接参数', base_fields, getter, changed, self._hint,
            self._registry, 'Diverter', columns=2, label_width=14)
        base_values.grid(row=0, column=0, sticky='nsew', padx=4, pady=3)
        domain_field = field_by_key['ExternalAllowedDomains']
        self.domain_list_widget = widgets.CsvListFieldWidget(
            base, domain_field, getter(domain_field.key), changed, self._hint,
            height=2)
        self.domain_list_widget.grid(row=0, column=1, sticky='nsew',
                                     padx=6, pady=6)
        self._registry[('Diverter', domain_field.key.lower())] = \
            self.domain_list_widget

        takeover = ttk.LabelFrame(
            self._egress_inner, text='将其他域名导向私网分析主机')
        takeover.grid(row=1, column=0, sticky='nsew', padx=3, pady=3)
        self.takeover_enabled_var = tk.BooleanVar(
            value='ExternalTakeoverIPv4' in self.model.diverter())
        self.takeover_check = ttk.Checkbutton(
            takeover, text='启用：放行域名保持真实访问，其余域名解析到指定私网 IPv4',
            variable=self.takeover_enabled_var,
            command=self._toggle_takeover)
        self.takeover_check.pack(anchor='w', padx=7, pady=(4, 1))
        widgets.attach_tooltip(
            self.takeover_check,
            '将其他域名导向私网分析主机\n'
            '放行域名保持真实访问；其余域名解析到指定私网 IPv4。启用后，'
            '真实联网域名按当前核心安全合同固定为唯一 api.deepseek.com。',
            self._hint,
            '放行域名保持真实访问；其余域名解析到指定私网 IPv4')
        takeover_fields = [field_by_key[key] for key in (
            'ExternalTakeoverIPv4', 'ExternalTakeoverDnsTTL',
            'ExternalTakeoverProbeTCPPorts',
            'ExternalTakeoverProbeTimeoutMs')]
        self.takeover_fields_frame = widgets.build_group_frame(
            takeover, '目标与提示性探测', takeover_fields, getter, changed,
            self._hint, self._registry, 'Diverter', columns=2,
            label_width=16)
        self.takeover_fields_frame.pack(fill='x', padx=3, pady=(0, 4))

        process = ttk.LabelFrame(
            self._egress_inner, text='按指定程序重定向公网 IPv4')
        process.grid(row=1, column=1, rowspan=2, sticky='nsew',
                     padx=3, pady=3)
        process_fields = [field_by_key[key] for key in (
            'ExternalProcessRedirectEnabled',
            'ExternalProcessRedirectImagePath',
            'ExternalProcessRedirectImageSHA256',
            'ExternalProcessRedirectOriginalIPv4',
            'ExternalProcessRedirectTargetIPv4')]
        process_values = widgets.build_group_frame(
            process, '单个目标程序', process_fields, getter, changed,
            self._hint, self._registry, 'Diverter', columns=2,
            label_width=16)
        process_values.pack(fill='x', padx=3, pady=3)

        public = ttk.LabelFrame(self._egress_inner, text='公网 IPv4 直连')
        public.grid(row=2, column=0, sticky='nsew', padx=3, pady=3)
        public_key = 'ExternalAllowedIPv4Rules'
        self.public_ipv4_enabled_var = tk.BooleanVar(
            value=public_key in self.model.diverter())
        self.public_ipv4_check = ttk.Checkbutton(
            public, text='启用审核后的公网 IPv4 规则',
            variable=self.public_ipv4_enabled_var,
            command=self._toggle_public_ipv4)
        self.public_ipv4_check.pack(anchor='w', padx=7, pady=(4, 1))
        widgets.attach_tooltip(
            self.public_ipv4_check,
            '公网 IPv4 直连\n启用后仅按下方协议、IPv4 和端口规则直连公网；'
            '规则仍受数量、协议和地址安全校验约束。',
            self._hint, '启用或停用审核后的公网 IPv4 直连规则')
        public_field = field_by_key[public_key]
        self.public_rules_widget = widgets.IPv4RulesFieldWidget(
            public, public_field, getter(public_key), changed, self._hint,
            height=3)
        self.public_rules_widget.pack(fill='both', expand=True,
                                      padx=7, pady=(1, 6))
        self._registry[('Diverter', public_key.lower())] = \
            self.public_rules_widget

        locked_fields = [field for field in schema.DIVERTER_FIELDS
                         if field.group in schema.egress_group_names()
                         and field.lock]
        details = ttk.Frame(self._egress_inner)
        details.grid(row=3, column=0, columnspan=2, sticky='ew',
                     padx=3, pady=(3, 5))
        self.egress_details_visible = False
        self.egress_details_button = ttk.Button(
            details, text='查看 %d 项安全约束' % len(locked_fields),
            command=self._toggle_egress_details)
        self.egress_details_button.pack(anchor='w')
        self.egress_details_frame = widgets.build_group_frame(
            details, '只读实现详情', locked_fields, getter, changed,
            self._hint, self._registry, 'Diverter', columns=2,
            label_width=19)

        for field in schema.DIVERTER_FIELDS:
            if field.group not in schema.egress_group_names():
                continue
            identity = ('Diverter', field.key.lower())
            if identity in self._registry:
                self._egress_widgets[field.key] = self._registry[identity]
        self._refresh_locks()

    def _render_static_tabs(self):
        """Compatibility/test helper; production still builds tabs lazily."""
        self._ensure_tab(0)
        self._ensure_tab(1)
        self._building = True
        try:
            self._render_global_tab()
            self._render_egress_tab()
        finally:
            self._building = False

    def _toggle_egress_details(self):
        self.egress_details_visible = not self.egress_details_visible
        if self.egress_details_visible:
            self.egress_details_frame.pack(fill='x', pady=(4, 0))
            self.egress_details_button.configure(text='隐藏安全约束')
        else:
            self.egress_details_frame.pack_forget()
            count = len([field for field in schema.DIVERTER_FIELDS
                         if field.group in schema.egress_group_names()
                         and field.lock])
            self.egress_details_button.configure(
                text='查看 %d 项安全约束' % count)

    def _toggle_takeover(self):
        if self._building or self._running:
            return
        diverter = self.model.diverter()
        enabled = self.takeover_enabled_var.get()
        if enabled:
            domains = {item.strip().lower() for item in
                       (diverter.get('ExternalAllowedDomains') or '').split(',')
                       if item.strip()}
            if domains != {'api.deepseek.com'} and not messagebox.askyesno(
                    '启用私网导向',
                    '此功能要求真实联网域名固定为唯一的 '
                    'api.deepseek.com。\n\n确认替换当前域名列表并继续?',
                    parent=self.root):
                self.takeover_enabled_var.set(False)
                return
            diverter.set('ExternalTakeoverIPv4', '')
            diverter.set('ExternalTakeoverDnsTTL', '60')
            diverter.set('ExternalTakeoverProbeTCPPorts', '')
            diverter.set('ExternalTakeoverProbeTimeoutMs', '500')
            diverter.set('ExternalAllowedDomains', 'api.deepseek.com')
            diverter.set('ExternalNonAllowedAction', 'Divert')
        else:
            for key in ('ExternalTakeoverIPv4', 'ExternalTakeoverDnsTTL',
                        'ExternalTakeoverProbeTCPPorts',
                        'ExternalTakeoverProbeTimeoutMs'):
                diverter.delete(key)
        self._mark_dirty()
        self._building = True
        try:
            self._render_egress_tab()
            changes = self._sync_active_egress_policy()
        finally:
            self._building = False
        if changes and 2 in self._tabs_built:
            self._refresh_listener_list()
        self._schedule_validate()

    def _toggle_public_ipv4(self):
        if self._building or self._running:
            return
        diverter = self.model.diverter()
        key = 'ExternalAllowedIPv4Rules'
        if self.public_ipv4_enabled_var.get():
            diverter.set(key, '')
        else:
            diverter.delete(key)
        self._mark_dirty()
        self._refresh_locks()
        self._schedule_validate()

    # ------------------------------------------------------------------
    # listeners tab
    # ------------------------------------------------------------------

    def _refresh_listener_list(self):
        if 2 not in self._tabs_built:
            return
        self.listener_list.delete(0, 'end')
        self.system_listener_list.delete(0, 'end')
        system_names = self._system_listener_names()
        names = [sec.name for sec in self.model.listener_sections()
                 if sec.name not in system_names]
        ordered_system = [sec.name for sec in self.model.listener_sections()
                          if sec.name in system_names]
        for name in names:
            self.listener_list.insert('end', name)
        for name in ordered_system:
            self.system_listener_list.insert('end', name)
        all_names = names + ordered_system
        if self._selected_listener not in all_names:
            self._selected_listener = names[0] if names else (
                ordered_system[0] if ordered_system else None)
        self.listener_list.selection_clear(0, 'end')
        self.system_listener_list.selection_clear(0, 'end')
        if self._selected_listener:
            if self._selected_listener in names:
                index = names.index(self._selected_listener)
                self.listener_list.selection_set(index)
                self.listener_list.activate(index)
            elif self._selected_listener in ordered_system:
                index = ordered_system.index(self._selected_listener)
                self.system_listener_list.selection_set(index)
                self.system_listener_list.activate(index)
        self._update_listener_action_states()
        self._render_listener_panel()

    def _system_listener_names(self):
        result = set()
        diverter = self.model.diverter()
        policy = (diverter.get('ExternalAccessPolicy') or '').strip().lower() \
            == schema.EGRESS_POLICY_ENABLED.lower()
        for sec in self.model.listener_sections():
            listener_class = (sec.get('Listener') or '').strip()
            if listener_class == 'DomainEgressRelay':
                result.add(sec.name)
                continue
            if not policy or listener_class != 'DNSListener' or \
                    (sec.get('Enabled') or 'True').strip().lower() not in \
                    ('true', 'yes', 'on', 'enabled'):
                continue
            try:
                on_53 = 53 in configmodel.expand_ports(sec.get('Port') or '')
            except ValueError:
                on_53 = False
            if on_53 and (sec.get('Protocol') or '').strip().upper() in \
                    ('TCP', 'UDP'):
                result.add(sec.name)
        return result

    def _selected_listener_is_system(self):
        return self._selected_listener in self._system_listener_names()

    def _update_listener_action_states(self):
        if 2 not in self._tabs_built:
            return
        locked = self._running or self._selected_listener_is_system()
        for index, button in enumerate(self.listener_action_buttons):
            # New is available without a selection; all other actions require
            # a user-managed listener.
            disabled = self._running or (index > 0 and (
                not self._selected_listener or locked))
            button.state(['disabled'] if disabled else ['!disabled'])
        diverter = self.model.diverter()
        policy = (diverter.get('ExternalAccessPolicy') or '').strip().lower() \
            == schema.EGRESS_POLICY_ENABLED.lower()
        self.regenerate_system_button.state(
            ['disabled'] if (self._running or not policy)
            else ['!disabled'])

    def _on_select_listener(self, _event=None):
        selection = self.listener_list.curselection()
        if not selection:
            return
        names = [sec.name for sec in self.model.listener_sections()]
        user_names = [name for name in names
                      if name not in self._system_listener_names()]
        self._selected_listener = user_names[selection[0]]
        self.system_listener_list.selection_clear(0, 'end')
        self._update_listener_action_states()
        self._render_listener_panel()

    def _on_select_system_listener(self, _event=None):
        selection = self.system_listener_list.curselection()
        if not selection:
            return
        system_names = [sec.name for sec in self.model.listener_sections()
                        if sec.name in self._system_listener_names()]
        self._selected_listener = system_names[selection[0]]
        self.listener_list.selection_clear(0, 'end')
        self._update_listener_action_states()
        self._render_listener_panel()

    def _regenerate_system_listeners(self):
        if self._running:
            return
        changes = self._sync_active_egress_policy()
        if changes:
            self._mark_dirty()
            self._hint('已重新生成并校验系统必需监听器')
        else:
            self._hint('系统必需监听器已完整,无需修改')
        self._refresh_listener_list()
        self._schedule_validate()

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
        # Dynamic listener redraw must preserve static FakeNet/Diverter field
        # registrations so validation double-click keeps working.
        self._registry = {
            k: v for k, v in self._registry.items()
            if k[0] in ('FakeNet', 'Diverter')}
        self._building = True
        try:
            frame = widgets.build_group_frame(
                self._listener_inner, '[%s]' % sec.name, fields,
                lambda key: sec.get(key, '') or '',
                self._on_listener_field, self._hint,
                self._registry, sec.name)
            frame.pack(fill='x', pady=4)
            readonly = self._running or self._selected_listener_is_system()
            if readonly:
                for field in fields:
                    widget = self._registry.get(
                        (sec.name, field.key.lower()))
                    if widget is not None:
                        widget.set_locked(
                            True, reason=('FakeNet 运行中' if self._running
                                          else '系统自动管理'))
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
                    if readonly:
                        entry.state(['disabled'])
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
        if (self._building or self._running or not self._selected_listener or
                self._selected_listener_is_system()):
            return
        sec = self.model.section(self._selected_listener)
        if (sec.get(key, '') or '') == value:
            return
        sec.set(key, value)
        self._mark_dirty()
        if key.lower() in ('enabled', 'listener', 'port', 'protocol'):
            self._refresh_listener_list()
        self._schedule_validate()

    def _on_extra_key(self, section_name, key, var):
        sec = self.model.section(section_name)
        if (sec is not None and not self._running and
                section_name not in self._system_listener_names() and
                (sec.get(key, '') or '') != var.get()):
            sec.set(key, var.get())
            self._mark_dirty()
            self._schedule_validate()

    def _listener_add(self):
        if self._running:
            return
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
        if (self._running or not self._selected_listener or
                self._selected_listener_is_system()):
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
        if (self._running or not self._selected_listener or
                self._selected_listener_is_system()):
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
        if (self._running or not self._selected_listener or
                self._selected_listener_is_system()):
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

    # ------------------------------------------------------------------
    # custom response tab
    # ------------------------------------------------------------------

    def _update_custom_content_state(self):
        has_sections = bool(self.custom_model is not None and
                            self.custom_model.sections)
        if not has_sections:
            self.custom_pane.pack_forget()
            if self.custom_model is None:
                self.custom_empty_title_var.set('尚未加载自定义响应文件')
                self.custom_empty_help_var.set(
                    '自定义响应文件由监听器中的 Custom 字段引用。\n'
                    '请打开已有 INI，或新建一个响应文件后添加配置段。')
                self.custom_empty_add_button.pack_forget()
            else:
                self.custom_empty_title_var.set('响应文件中还没有配置段')
                self.custom_empty_help_var.set(
                    '新增一个配置段后即可编辑响应内容。')
                if not self.custom_empty_add_button.winfo_manager():
                    self.custom_empty_add_button.pack(pady=(4, 0))
            if not self.custom_empty.winfo_manager():
                self.custom_empty.pack(fill='both', expand=True)
        else:
            self.custom_empty.pack_forget()
            if not self.custom_pane.winfo_manager():
                self.custom_pane.pack(fill='both', expand=True, padx=6,
                                      pady=(0, 6))

    def _custom_open(self):
        if self._running:
            return
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
        if self._running:
            return
        model = configmodel.ConfigModel()
        model.kind = 'custom'
        model.path = None
        self.custom_model = model
        self._custom_selected = None
        self.custom_status.set('未命名(新建)')
        self._update_custom_content_state()
        self._refresh_custom_list()

    def _custom_save(self):
        if self._running:
            return
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
        names = [sec.name for sec in self.custom_model.sections.values()]
        for name in names:
            self.custom_list.insert('end', name)
        if names:
            self.custom_list.selection_set(0)
            self._custom_selected = names[0]
        self._update_custom_content_state()
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
        self._custom_registry = {}
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
            self._hint, self._custom_registry, sec.name)
        frame.pack(fill='x', pady=4)
        if self._running:
            for widget in self._custom_registry.values():
                widget.set_locked(True, reason='FakeNet 运行中')

    def _on_custom_field(self, section_name, key, value):
        if self._running:
            return
        sec = self.custom_model.section(section_name)
        if sec is not None and (sec.get(key, '') or '') != value:
            sec.set(key, value)
            self._render_custom_panel()

    def _custom_add(self):
        if self._running:
            return
        if self.custom_model is None:
            self._custom_new()
        name = self._prompt_name('新增自定义响应段', 'Example New')
        if not name:
            return
        self.custom_model.ensure_section(name)
        self._custom_selected = name
        self._refresh_custom_list()

    def _custom_delete(self):
        if (self._running or self.custom_model is None or
                not self._custom_selected):
            return
        self.custom_model.delete_section(self._custom_selected)
        self._custom_selected = None
        self._refresh_custom_list()

    # ------------------------------------------------------------------
    # file operations
    # ------------------------------------------------------------------

    def new_config(self):
        if self._running:
            return
        self.logger.info('new configuration requested')
        self.model = configmodel.ConfigModel.new_config()
        self.model.path = None
        self._selected_listener = None
        self._rebuild_all()
        self._clear_dirty()

    def open_file(self):
        if self._running:
            return
        if not self._confirm_discard():
            return
        path = filedialog.askopenfilename(
            parent=self.root, filetypes=[('INI', '*.ini'), ('所有', '*.*')])
        if not path:
            return
        self._load_path(path)

    def restore_defaults(self):
        if self._running:
            return
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

        self.logger.info('default configuration restored: path=%s', path)
        self.model = replacement
        self._selected_listener = None
        self._rebuild_all()
        self._clear_dirty()

    def load_template(self, name):
        if self._running:
            return
        if not self._confirm_discard():
            return
        for directory in self._template_dirs():
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                self._load_path(path)
                return
        messagebox.showerror('模板载入', '模板不存在: %s' % name)

    def _load_path(self, path):
        self.logger.info('configuration load requested: path=%s', path)
        try:
            model = configmodel.ConfigModel.load(path)
        except Exception as exc:  # noqa: BLE001 - surfaced to the user
            messagebox.showerror('打开', '无法解析配置文件:\n%s' % exc)
            return
        model.ensure_sections()
        self.model = model
        self._selected_listener = None
        changes = self._rebuild_all()
        if changes:
            self._mark_dirty()
        else:
            self._clear_dirty()
        self.logger.info(
            'configuration loaded: path=%s encoding=%s bom=%s newline=%r '
            'automatic_changes=%d', self.model.path, self.model.encoding,
            self.model.bom, self.model.newline, len(changes))

    def _rebuild_all(self):
        changes = []
        self._hash_generation += 1
        self._hash_pending = False
        self._hash_issue = None
        self._registry = {}
        self._egress_widgets = {}
        self._building = True
        try:
            changes = self._sync_active_egress_policy()
            if 0 in self._tabs_built:
                self._render_global_tab()
            if 1 in self._tabs_built:
                self._render_egress_tab()
        finally:
            self._building = False
        if 2 in self._tabs_built:
            self._refresh_listener_list()
        if 3 in self._tabs_built:
            self._update_custom_content_state()
        diverter = self.model.diverter()
        if (diverter.get('ExternalProcessRedirectEnabled') or '').strip() \
                .lower() == 'yes':
            self._start_process_hash(
                diverter.get('ExternalProcessRedirectImagePath') or '',
                update_model=False)
        if self._validate_job is not None:
            try:
                self.root.after_cancel(self._validate_job)
            except tk.TclError:
                pass
        self._validate_job = self.root.after_idle(self._validate_now)
        return changes

    def _confirm_discard(self):
        if not self.dirty:
            return True
        return messagebox.askyesno(
            '未保存的修改', '当前配置有未保存的修改,放弃并继续?')

    def save(self, as_else=False):
        if self._running or self.model is None:
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
        self.logger.info('configuration saved: path=%s', self.model.path)

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
        if self._running:
            return
        errors = [i for i in self._issues if i.level == validator.ERROR]
        if errors:
            self.open_validation_window()
            self._hint('存在 %d 个校验错误,已打开完整详情' % len(errors))
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
        self.logger.info('FakeNet launch requested: config=%s',
                         self.model.path)
        threading.Thread(target=self._launch_gates, daemon=True).start()

    def _launch_gates(self):
        # Duplicate-instance gate (P3).
        if launcher.is_fakenet_running():
            self.logger.warning('FakeNet launch refused: duplicate process')
            self._ui(lambda: self._launch_abort(
                '检测到 fakenet.exe 已在运行。\n请先停止现有实例再启动'
                '(双 WinDivert 句柄属未定义行为)。'))
            return
        # VM gate (fail-closed, F1) - runs off the UI thread (P7).
        vm = launcher.query_vm_state()
        self.logger.info('VM gate verdict=%s detail=%s', vm.verdict,
                         vm.detail)
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
        self._update_action_states()
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
        try:
            # The explicit core log always belongs beside the selected
            # fakenet.exe, even when this GUI itself is running from source.
            log_base = os.path.dirname(exe)
            log_path = startup_logging.reserve_fakenet_log_path(
                base_dir=log_base)
            if getattr(sys, 'frozen', False):
                target, params, directory = launcher.build_frozen_command(
                    exe, config_path, log_path)
            else:
                target, params, directory = launcher.build_dev_command(
                    config_path, log_path)
        except (OSError, launcher.LaunchError) as exc:
            self._launch_abort('无法创建本次 FakeNet 日志:\n%s' % exc)
            return
        launched, detail, process_handle = \
            launcher.launch_elevated_with_handle(target, params, directory)
        self.logger.info(
            'FakeNet elevation result: launched=%s detail=%s exe=%s '
            'config=%s log=%s handle=%s', launched, detail, exe,
            config_path, log_path, bool(process_handle))
        if not launched:
            try:
                os.remove(log_path)
            except OSError:
                pass
            messagebox.showwarning('启动', detail)
            self._update_action_states()
            return
        if not process_handle:
            self._launch_abort(
                'FakeNet-NG 已请求启动,但未取得进程句柄;'
                '无法安全管理本次运行状态。')
            return
        self._begin_fakenet_session(log_path, process_handle)
        message = '已启动 FakeNet-NG;配置已锁定,实时日志已打开。'
        if note:
            message += ' %s' % note
        self._hint(message)

    def _begin_fakenet_session(self, log_path, process_handle):
        self._fakenet_log_path = os.path.abspath(log_path)
        self._fakenet_process_handle = process_handle
        self._log_offset = 0
        self._log_decoder = codecs.getincrementaldecoder('utf-8')(
            errors='replace')
        self._log_large_warned = False
        self._ensure_tab(4)
        self.log_path_var.set(self._fakenet_log_path)
        self.log_state_var.set('FakeNet-NG 正在启动,等待日志内容…')
        self.open_log_dir_button.state(['!disabled'])
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', 'end')
        self.log_text.configure(state='disabled')
        self.notebook.select(4)
        self._set_running_state(True)
        self.logger.info('FakeNet session started: log=%s',
                         self._fakenet_log_path)
        self._poll_log()

        def wait_for_exit():
            code = None
            error = None
            try:
                code = launcher.wait_process(process_handle)
            except OSError as exc:
                error = str(exc)
            finally:
                launcher.close_handle(process_handle)
            self._ui(lambda: self._finish_fakenet_session(
                process_handle, code, error))

        threading.Thread(target=wait_for_exit, name='FakeNetProcessWait',
                         daemon=True).start()

    def _set_running_state(self, running):
        self._running = bool(running)
        if running:
            self._refresh_locks()
            if 2 in self._tabs_built:
                self._render_listener_panel()
        else:
            self._building = True
            try:
                if 0 in self._tabs_built:
                    self._render_global_tab()
                if 1 in self._tabs_built:
                    self._render_egress_tab()
            finally:
                self._building = False
            if 2 in self._tabs_built:
                self._refresh_listener_list()
            diverter = self.model.diverter()
            if (diverter.get('ExternalProcessRedirectEnabled') or '').strip() \
                    .lower() == 'yes':
                self._start_process_hash(
                    diverter.get('ExternalProcessRedirectImagePath') or '',
                    update_model=False)
        self._update_action_states()

    def _finish_fakenet_session(self, process_handle, exit_code, error):
        if self._fakenet_process_handle != process_handle:
            return
        self._fakenet_process_handle = None
        if self._log_job is not None:
            try:
                self.root.after_cancel(self._log_job)
            except tk.TclError:
                pass
            self._log_job = None
        self._poll_log(schedule=False, final=True)
        if error:
            self.log_state_var.set('无法取得 FakeNet-NG 退出状态: %s' % error)
            self.logger.error('FakeNet session wait failed: %s', error)
        else:
            self.log_state_var.set('FakeNet-NG 已退出（退出码 %s）' % exit_code)
            self.logger.info('FakeNet session exited: code=%s log=%s',
                             exit_code, self._fakenet_log_path)
        self._set_running_state(False)
        self._validate_now()

    def _append_log_text(self, text):
        if not text or 4 not in self._tabs_built:
            return
        self.log_text.configure(state='normal')
        self.log_text.insert('end', text)
        self.log_text.configure(state='disabled')
        if not self.log_pause_var.get():
            self.log_text.see('end')

    def _poll_log(self, schedule=True, final=False):
        self._log_job = None
        path = self._fakenet_log_path
        if path and os.path.isfile(path):
            try:
                size = os.path.getsize(path)
                with open(path, 'rb') as handle:
                    handle.seek(self._log_offset)
                    data = handle.read()
                self._log_offset += len(data)
                if data:
                    self._append_log_text(self._log_decoder.decode(data))
                if final:
                    self._append_log_text(self._log_decoder.decode(b'', True))
                if size > LOG_LARGE_BYTES and not self._log_large_warned:
                    self._log_large_warned = True
                    self.log_state_var.set(
                        '日志已超过 25 MiB;仍完整显示,界面操作可能变慢。')
            except OSError as exc:
                self.log_state_var.set('读取实时日志失败: %s' % exc)
        if schedule and self._running:
            self._log_job = self.root.after(LOG_POLL_MS, self._poll_log)

    def _open_log_directory(self):
        if not self._fakenet_log_path:
            return
        directory = os.path.dirname(self._fakenet_log_path)
        try:
            os.startfile(directory)
        except (AttributeError, OSError) as exc:
            messagebox.showwarning('打开日志目录', str(exc), parent=self.root)

    def _ui(self, func):
        """Queue a callback for Tk's main thread without touching Tk here."""
        self._ui_queue.put(func)

    def _drain_ui_queue(self):
        self._ui_job = None
        try:
            while True:
                callback = self._ui_queue.get_nowait()
                try:
                    callback()
                except tk.TclError:
                    continue
        except queue.Empty:
            pass
        try:
            if self.root.winfo_exists():
                self._ui_job = self.root.after(25, self._drain_ui_queue)
        except tk.TclError:
            self._ui_job = None

    # ------------------------------------------------------------------
    # misc
    # ------------------------------------------------------------------

    def _jump_to_issue(self, _event=None):
        if self.panel is None:
            return
        selection = self.panel.selection()
        if not selection:
            return
        values = self.panel.item(selection[0], 'values')
        location = values[1] if len(values) > 1 else ''
        if not location.startswith('['):
            return
        section = location[1:location.index(']')] if ']' in location else ''
        key = location.split(' ', 1)[1] if ' ' in location else ''
        if section == 'FakeNet':
            self._ensure_tab(0)
        elif section == 'Diverter':
            field = schema.diverter_field(key)
            self._ensure_tab(
                1 if field and field.group in schema.egress_group_names()
                else 0)
        elif section:
            self._ensure_tab(2)
            self._selected_listener = section
            self._refresh_listener_list()
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
        if self.panel is None or self._panel_menu is None:
            return
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
        if self.panel is None:
            return
        rows = [self.panel.item(iid)['values']
                for iid in self.panel.selection()]
        if not rows:
            self._hint('请先选中要复制的行(可按住 Ctrl 多选)')
            return
        self._copy_to_clipboard(
            '\n'.join(self._row_text(row) for row in rows))

    def _copy_all_issues(self):
        if self.panel is None:
            return
        rows = [self.panel.item(iid)['values']
                for iid in self.panel.get_children()]
        if not rows:
            self._hint('当前没有校验结果')
            return
        self._copy_to_clipboard(
            '\n'.join(self._row_text(row) for row in rows))

    def _show_full_issue(self):
        if self.panel is None:
            return
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
            '启动(带 VM/重复实例安全门)。\n方案: PLAN/2026.08.14 v1.13')

    def _on_close(self):
        if self._running and not messagebox.askyesno(
                '退出', 'FakeNet-NG 仍在运行。关闭配置工具不会停止它,'
                '也将停止实时日志显示。\n\n确定关闭?', parent=self.root):
            return
        if self.dirty and not messagebox.askyesno('退出',
                                                  '有未保存的修改,确定退出?'):
            return
        if self._log_job is not None:
            try:
                self.root.after_cancel(self._log_job)
            except tk.TclError:
                pass
            self._log_job = None
        self._close_validation_window()
        self.root.destroy()

    def _on_root_destroy(self, event):
        if event.widget is not self.root:
            return
        for job_name in ('_validate_job', '_log_job', '_ui_job'):
            job = getattr(self, job_name, None)
            if job is not None:
                try:
                    self.root.after_cancel(job)
                except tk.TclError:
                    pass
                setattr(self, job_name, None)
