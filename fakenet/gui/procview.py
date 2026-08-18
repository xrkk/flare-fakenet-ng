# -*- coding: utf-8 -*-
"""Per-process network access view (plan v1.32 12.32.2).

Readonly Toplevel window fed by incremental fakenet.log text. It parses
PROCESS_FLOW events emitted by the diverter (one per outbound flow, with
pid/process attribution and the diverter verdict) and groups them into a
two-level tree: process node -> flow rows. Filtering: process-name
substring, exact PID and disposition. The window never touches the main
configuration flow.
"""

import os
import re
import threading
import tkinter as tk
from tkinter import filedialog, ttk

PROCESS_FLOW_RE = re.compile(
    r'^(?P<time>\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?: AM| PM)?)\s+'
    r'\[[^]]+\]\s+(?P<who>\S+)\s+PROCESS_FLOW\s+(?P<fields>.+)$')

FIELD_RE = re.compile(r'(\w+)=("([^"]*)"|\S+)')

DISPOSITIONS = (
    '全部', 'DIVERT_FAKE', 'REDIRECT_TLS_RELAY', 'ALLOW_TAKEOVER_SINK',
    'ALLOW_REVIEWED_IP', 'ALLOW_INTERNAL_UPSTREAM', 'REINJECT_LOCAL',
    'DROP_EXTERNAL')

MAX_ROWS = 20000


def parse_process_flow_line(line):
    """Parse one log line; return a flow dict or None."""
    match = PROCESS_FLOW_RE.match(line.strip())
    if not match:
        return None
    fields = {}
    for pair in FIELD_RE.finditer(match.group('fields')):
        fields[pair.group(1)] = pair.group(3) if pair.group(3) is not None \
            else pair.group(2)
    if 'pid' not in fields or 'process' not in fields:
        return None
    fields['time'] = match.group('time')
    fields['source'] = match.group('who')
    return fields


class ProcessFlowWindow(object):
    """Window controller; `feed()` is called with incremental log text."""

    POLL_MS = 500

    def __init__(self, parent, app):
        self.app = app
        self.rows = []            # all parsed flows (bounded)
        self.filter_name = ''
        self.filter_pid = ''
        self.filter_disposition = DISPOSITIONS[0]
        self.paused = False
        self.follow = True
        self._file_path = None
        self._file_offset = 0
        self._file_job = None

        self.window = tk.Toplevel(parent)
        self.window.title('进程网络访问视图')
        self.window.geometry('980x560')
        self.window.transient(parent)

        toolbar = ttk.Frame(self.window)
        toolbar.grid(row=0, column=0, sticky='ew', padx=6, pady=4)
        ttk.Label(toolbar, text='进程名包含:').grid(row=0, column=0)
        self.name_var = tk.StringVar()
        self.name_var.trace_add('write', self._filters_changed)
        ttk.Entry(toolbar, textvariable=self.name_var, width=18)\
            .grid(row=0, column=1, padx=(2, 10))
        ttk.Label(toolbar, text='PID:').grid(row=0, column=2)
        self.pid_var = tk.StringVar()
        self.pid_var.trace_add('write', self._filters_changed)
        ttk.Entry(toolbar, textvariable=self.pid_var, width=8)\
            .grid(row=0, column=3, padx=(2, 10))
        ttk.Label(toolbar, text='处置:').grid(row=0, column=4)
        self.disp_var = tk.StringVar(value=DISPOSITIONS[0])
        self.disp_var.trace_add('write', self._filters_changed)
        ttk.Combobox(toolbar, textvariable=self.disp_var, width=22,
                     state='readonly', values=DISPOSITIONS)\
            .grid(row=0, column=5, padx=(2, 10))
        self.pause_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(toolbar, text='暂停', variable=self.pause_var)\
            .grid(row=0, column=6, padx=(0, 6))
        self.follow_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text='自动滚动', variable=self.follow_var)\
            .grid(row=0, column=7, padx=(0, 6))
        ttk.Button(toolbar, text='清空', command=self._clear)\
            .grid(row=0, column=8, padx=(0, 6))
        ttk.Button(toolbar, text='打开日志文件…',
                   command=self._open_log_dialog)\
            .grid(row=0, column=9)

        columns = ('target', 'proto', 'disposition', 'domain', 'time')
        headers = ('目标', '协议', '处置', '域名', '时间')
        frame = ttk.Frame(self.window)
        frame.grid(row=1, column=0, sticky='nsew', padx=6, pady=(0, 4))
        self.window.rowconfigure(1, weight=1)
        self.window.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(frame, columns=columns, show='tree headings')
        self.tree.heading('#0', text='进程 (PID)')
        for key, title in zip(columns, headers):
            self.tree.heading(key, text=title)
        self.tree.column('#0', width=220, stretch=False)
        self.tree.column('target', width=190, anchor='w')
        self.tree.column('proto', width=55, anchor='center')
        self.tree.column('disposition', width=150, anchor='w')
        self.tree.column('domain', width=180, anchor='w')
        self.tree.column('time', width=130, anchor='w')
        scrollbar = ttk.Scrollbar(frame, orient='vertical',
                                  command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        scrollbar.grid(row=0, column=1, sticky='ns')

        self.status_var = tk.StringVar(value='等待 PROCESS_FLOW 事件…')
        ttk.Label(self.window, textvariable=self.status_var,
                  relief='sunken', anchor='w')\
            .grid(row=2, column=0, sticky='ew', padx=6, pady=(0, 4))

        self.window.protocol('WM_DELETE_WINDOW', self._close)
        self._render_lock = threading.Lock()

    # -- data ingest -------------------------------------------------------

    def feed(self, text):
        """Consume incremental decoded log text (any thread-safe caller is
        fine: only ever invoked from the Tk main loop via the app)."""
        if not text or self.paused:
            return
        added = False
        for line in text.splitlines():
            flow = parse_process_flow_line(line)
            if flow is not None:
                self.rows.append(flow)
                added = True
        if len(self.rows) > MAX_ROWS:
            del self.rows[:len(self.rows) - MAX_ROWS]
        if added:
            self._rebuild()

    # -- rendering ---------------------------------------------------------

    def _visible(self, flow):
        if self.filter_name and self.filter_name.lower() not in \
                flow.get('process', '').lower():
            return False
        if self.filter_pid and flow.get('pid', '') != self.filter_pid:
            return False
        if (self.filter_disposition != DISPOSITIONS[0] and
                flow.get('disposition') != self.filter_disposition):
            return False
        return True

    def _rebuild(self):
        with self._render_lock:
            try:
                selection = self.tree.selection()
                self.tree.delete(*self.tree.get_children(''))
            except tk.TclError:
                return
            grouped = {}
            for flow in self.rows:
                if self._visible(flow):
                    grouped.setdefault(
                        (flow.get('pid', '?'), flow.get('process', '?')),
                        []).append(flow)
            for (pid, process), flows in sorted(
                    grouped.items(), key=lambda item: int(item[0][0])
                    if str(item[0][0]).isdigit() else 1 << 30):
                node = self.tree.insert(
                    '', 'end', text='[%s] %s (%d)' % (pid, process,
                                                      len(flows)),
                    open=True, values=('', '', '', '', ''))
                for flow in flows:
                    self.tree.insert(
                        node, 'end',
                        text='',
                        values=(
                            '%s:%s' % (flow.get('dst', '?'),
                                       flow.get('dport', '?')),
                            flow.get('proto', '?'),
                            flow.get('disposition', '?'),
                            flow.get('domain', '-') or '-',
                            flow.get('time', '')))
            if selection:
                try:
                    for item in selection:
                        self.tree.selection_add(item)
                except tk.TclError:
                    pass
            if self.follow_var.get():
                children = self.tree.get_children('')
                if children:
                    try:
                        self.tree.see(children[-1])
                    except tk.TclError:
                        pass
            self.status_var.set(
                '%d 条流(过滤后 %d 条,共 %d 个进程)' % (
                    len(self.rows), sum(
                        len(flows) for flows in grouped.values()),
                    len(grouped)))

    def _filters_changed(self, *_args):
        self.filter_name = self.name_var.get().strip()
        self.filter_pid = self.pid_var.get().strip()
        self.filter_disposition = self.disp_var.get()
        self._rebuild()

    def _clear(self):
        self.rows = []
        self._rebuild()

    # -- standalone log-file mode ------------------------------------------

    def _open_log_dialog(self):
        path = filedialog.askopenfilename(
            parent=self.window, filetypes=[('日志', '*.log'), ('所有', '*.*')])
        if not path:
            return
        self._file_path = path
        self._file_offset = 0
        self._clear()
        self._poll_file()

    def _poll_file(self):
        self._file_job = None
        if self._file_path and os.path.isfile(self._file_path):
            try:
                with open(self._file_path, 'r', encoding='utf-8',
                          errors='replace') as handle:
                    handle.seek(self._file_offset)
                    data = handle.read()
                    self._file_offset = handle.tell()
                if data:
                    self.feed(data)
            except OSError:
                pass
        if self._file_job is None and self.window.winfo_exists():
            self._file_job = self.window.after(
                self.POLL_MS, self._poll_file)

    def _close(self):
        if self._file_job is not None:
            try:
                self.window.after_cancel(self._file_job)
            except (tk.TclError, ValueError):
                pass
        try:
            self.app._procview_closed()
        except Exception:
            pass
        self.window.destroy()
