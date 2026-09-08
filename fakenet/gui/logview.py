# -*- coding: utf-8 -*-
"""Structured view for every entry in a FakeNet file log.

Unlike ``procview``, this module treats the ``pid=`` value in the logging
header as the PID.  Process-network attribution remains a separate view
because a PROCESS_FLOW message also contains a different, business-process
PID.
"""

import os
import re
import threading
import tkinter as tk
from tkinter import filedialog, ttk


LOG_LINE_RE = re.compile(
    r'^(?P<time>\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?: AM| PM)?)\s+'
    r'\[(?P<level>[^]]+)\]\s+\[(?P<logger>[^]]+)\]\s+'
    r'pid=(?P<pid>\d+)\s+thread=(?P<thread>\S+)\s*(?P<message>.*)$')

LEVELS = ('全部', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
MAX_ROWS = 20000


def parse_log_line(line):
    """Parse one FakeNet file-log header line, or return ``None``."""
    match = LOG_LINE_RE.match(line.rstrip('\r\n'))
    if not match:
        return None
    row = match.groupdict()
    row['level'] = row['level'].strip()
    row['logger'] = row['logger'].strip()
    return row


class LogGridWindow(object):
    """Readonly, filterable grid for the complete current FakeNet log."""

    POLL_MS = 500

    def __init__(self, parent, app, file_path=None):
        self.app = app
        self.rows = []
        self.filter_text = ''
        self.filter_pid = ''
        self.filter_level = LEVELS[0]
        self._file_path = None
        self._file_offset = 0
        self._file_job = None
        self._render_lock = threading.Lock()

        self.window = tk.Toplevel(parent)
        self.window.title('日志网格视图')
        self.window.geometry('1320x620%s' % self._center_over_parent(
            parent, 1320, 620))
        self.window.transient(parent)

        toolbar = ttk.Frame(self.window)
        toolbar.grid(row=0, column=0, sticky='ew', padx=6, pady=4)
        ttk.Label(toolbar, text='文本包含:').grid(row=0, column=0)
        self.text_var = tk.StringVar()
        self.text_var.trace_add('write', self._filters_changed)
        ttk.Entry(toolbar, textvariable=self.text_var, width=28)\
            .grid(row=0, column=1, padx=(2, 10))
        ttk.Label(toolbar, text='日志 PID:').grid(row=0, column=2)
        self.pid_var = tk.StringVar()
        self.pid_var.trace_add('write', self._filters_changed)
        ttk.Entry(toolbar, textvariable=self.pid_var, width=9)\
            .grid(row=0, column=3, padx=(2, 10))
        ttk.Label(toolbar, text='级别:').grid(row=0, column=4)
        self.level_var = tk.StringVar(value=LEVELS[0])
        self.level_var.trace_add('write', self._filters_changed)
        ttk.Combobox(toolbar, textvariable=self.level_var, width=12,
                     state='readonly', values=LEVELS)\
            .grid(row=0, column=5, padx=(2, 10))
        self.follow_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text='自动滚动', variable=self.follow_var)\
            .grid(row=0, column=6, padx=(0, 6))
        ttk.Button(toolbar, text='清空', command=self._clear)\
            .grid(row=0, column=7, padx=(0, 6))
        ttk.Button(toolbar, text='打开日志文件…',
                   command=self._open_log_dialog)\
            .grid(row=0, column=8)

        columns = ('time', 'level', 'logger', 'pid', 'thread', 'message')
        headers = ('时间', '级别', '记录器', 'PID', '线程', '消息')
        frame = ttk.Frame(self.window)
        frame.grid(row=1, column=0, sticky='nsew', padx=6, pady=(0, 4))
        self.window.rowconfigure(1, weight=1)
        self.window.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(frame, columns=columns, show='headings')
        for key, title in zip(columns, headers):
            self.tree.heading(key, text=title)
        self.tree.column('time', width=155, stretch=False)
        self.tree.column('level', width=85, stretch=False)
        self.tree.column('logger', width=135, stretch=False)
        self.tree.column('pid', width=75, stretch=False)
        self.tree.column('thread', width=120, stretch=False)
        self.tree.column('message', width=650, anchor='w')
        ybar = ttk.Scrollbar(frame, orient='vertical',
                             command=self.tree.yview)
        xbar = ttk.Scrollbar(frame, orient='horizontal',
                             command=self.tree.xview)
        self.tree.configure(yscrollcommand=ybar.set,
                            xscrollcommand=xbar.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        ybar.grid(row=0, column=1, sticky='ns')
        xbar.grid(row=1, column=0, sticky='ew')

        self.status_var = tk.StringVar(value='等待日志事件…')
        ttk.Label(self.window, textvariable=self.status_var,
                  relief='sunken', anchor='w')\
            .grid(row=2, column=0, sticky='ew', padx=6, pady=(0, 4))
        self.window.protocol('WM_DELETE_WINDOW', self._close)
        if file_path:
            self.follow_file(file_path)

    @staticmethod
    def _center_over_parent(parent, width, height):
        x = parent.winfo_x() + (parent.winfo_width() - width) // 2
        y = parent.winfo_y() + (parent.winfo_height() - height) // 2
        x = max(0, min(x, max(0, parent.winfo_screenwidth() - width)))
        y = max(0, min(y, max(0, parent.winfo_screenheight() - height)))
        return '+%d+%d' % (x, y)

    def feed(self, text):
        """Consume decoded file-log text and retain traceback continuations."""
        if not text:
            return
        changed = False
        for line in text.splitlines():
            row = parse_log_line(line)
            if row is not None:
                self.rows.append(row)
                changed = True
            elif self.rows and line:
                self.rows[-1]['message'] += '\n' + line
                changed = True
        if len(self.rows) > MAX_ROWS:
            del self.rows[:len(self.rows) - MAX_ROWS]
        if changed:
            self._rebuild()

    def visible_rows(self):
        needle = self.filter_text.lower()
        visible = []
        for row in self.rows:
            if self.filter_pid and row.get('pid') != self.filter_pid:
                continue
            if self.filter_level != LEVELS[0] and \
                    row.get('level') != self.filter_level:
                continue
            haystack = ' '.join((row.get('logger', ''),
                                 row.get('thread', ''),
                                 row.get('message', ''))).lower()
            if needle and needle not in haystack:
                continue
            visible.append(row)
        return visible

    def _rebuild(self):
        with self._render_lock:
            try:
                self.tree.delete(*self.tree.get_children(''))
            except tk.TclError:
                return
            visible = self.visible_rows()
            for row in visible:
                self.tree.insert('', 'end', values=(
                    row.get('time', ''), row.get('level', ''),
                    row.get('logger', ''), row.get('pid', ''),
                    row.get('thread', ''), row.get('message', '')))
            if self.follow_var.get():
                children = self.tree.get_children('')
                if children:
                    self.tree.see(children[-1])
            self.status_var.set('%d 条日志(过滤后 %d 条)' %
                                (len(self.rows), len(visible)))

    def _filters_changed(self, *_args):
        self.filter_text = self.text_var.get().strip()
        self.filter_pid = self.pid_var.get().strip()
        self.filter_level = self.level_var.get()
        self._rebuild()

    def _clear(self):
        self.rows = []
        self._rebuild()

    def follow_file(self, path):
        """Backfill ``path`` from byte zero, then continue following it."""
        self._file_path = os.path.abspath(path)
        self._file_offset = 0
        self._clear()
        self._poll_file()

    def _open_log_dialog(self):
        path = filedialog.askopenfilename(
            parent=self.window, filetypes=[('日志', '*.log'), ('所有', '*.*')])
        if path:
            self.follow_file(path)

    def _poll_file(self):
        if self._file_job is not None:
            try:
                self.window.after_cancel(self._file_job)
            except (tk.TclError, ValueError):
                pass
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
        if self.window.winfo_exists():
            self._file_job = self.window.after(self.POLL_MS, self._poll_file)

    def _close(self):
        if self._file_job is not None:
            try:
                self.window.after_cancel(self._file_job)
            except (tk.TclError, ValueError):
                pass
        try:
            self.app._logview_closed()
        except (AttributeError, TypeError):
            pass
        self.window.destroy()
