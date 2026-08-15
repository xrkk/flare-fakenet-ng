# -*- coding: utf-8 -*-
"""Field widgets for the fakenet-GUI GUI (plan v0.2 §5.1/§5.4).

One FieldWidget per schema.Field: label, type-specific input, lock badge,
focus-driven hint callback.  Locked widgets render read-only with a
'代码强制' badge; a forced value can be applied while locking.
"""

import hashlib
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from fakenet.gui import schema


class FieldWidget(ttk.Frame):

    def __init__(self, parent, field, value='', on_change=None,
                 on_focus=None, label_width=12):
        ttk.Frame.__init__(self, parent)
        self.field = field
        self.on_change = on_change
        self.on_focus = on_focus
        self._lock_badge = None
        self._multiline = False
        self._bool_literals = None

        self.columnconfigure(1, weight=1)
        title = '%s:' % field.label + ('（仅保真）' if field.dead else '')
        self.label = ttk.Label(
            self, text=title, width=label_width, anchor='e',
            justify='right', wraplength=max(80, label_width * 8))
        self.label.grid(row=0, column=0, sticky='ne', padx=(0, 6), pady=1)

        wtype = field.wtype
        if wtype in (schema.T_BOOL_YESNO, schema.T_BOOL_TRUEFALSE):
            values = (('Yes', 'No') if wtype == schema.T_BOOL_YESNO
                      else ('True', 'False'))
            self._bool_literals = values
            self.variable = tk.BooleanVar(value=value != values[1])
            self.input = ttk.Checkbutton(
                self, text='启用', variable=self.variable,
                command=self._changed, takefocus=True)
            self.input.grid(row=0, column=1, sticky='w', pady=1)
        elif wtype in (schema.T_ENUM, schema.T_IPV4_OR_ENUM):
            values = list(field.enum or ())
            if wtype == schema.T_IPV4_OR_ENUM:
                values = [''] + [v for v in values if v]
            self.variable = tk.StringVar(value=value)
            longest = max([len(str(item)) for item in values] +
                          [len(value or '')])
            width = max(10, min(32, longest + 2))
            self.input = ttk.Combobox(self, textvariable=self.variable,
                                      values=values, width=width)
            self.input.bind('<<ComboboxSelected>>', self._changed)
            self.input.bind('<FocusOut>', self._changed)
            self.input.grid(row=0, column=1, sticky='w', pady=1)
        elif wtype == schema.T_TEXT or field.key.lower() == 'listeners':
            self._multiline = True
            self.variable = None
            height = 3 if wtype == schema.T_TEXT else 2
            self.input = tk.Text(self, height=height, width=40, wrap='word',
                                 undo=True)
            self.input.insert('1.0', value)
            self.input.bind('<FocusOut>', self._changed)
            self.input.grid(row=0, column=1, sticky='nsew', pady=2)
        elif wtype in (schema.T_PATH_FILE, schema.T_PATH_DIR):
            box = ttk.Frame(self)
            box.grid(row=0, column=1, sticky='we', pady=1)
            box.columnconfigure(0, weight=1)
            self.variable = tk.StringVar(value=value)
            entry = ttk.Entry(box, textvariable=self.variable)
            entry.grid(row=0, column=0, sticky='we')
            entry.bind('<FocusOut>', self._changed)
            text = '浏览文件…' if wtype == schema.T_PATH_FILE else '浏览目录…'
            ttk.Button(box, text=text, width=10,
                       command=self._browse).grid(row=0, column=1,
                                                  sticky='e', padx=(4, 0))
            self.input = entry
        else:
            self.variable = tk.StringVar(value=value)
            self.input = ttk.Entry(self, textvariable=self.variable)
            self.input.bind('<FocusOut>', self._changed)
            self.input.grid(row=0, column=1, sticky='we', pady=1)

        if wtype == schema.T_HEX64:
            ttk.Button(self, text='计算文件哈希', width=14,
                       command=self._hash_file)\
                .grid(row=1, column=1, sticky='w')
        for widget in (self.input, self.label):
            widget.bind('<FocusIn>', self._focused)

    # -- events --------------------------------------------------------------

    def _focused(self, _event=None):
        if self.on_focus and self.field.hint:
            self.on_focus(self.field.hint)

    def _changed(self, _event=None):
        if self.on_change:
            self.on_change(self.field.key, self.get())

    def _browse(self):
        if self.field.wtype == schema.T_PATH_FILE:
            choice = filedialog.askopenfilename(parent=self)
        else:
            choice = filedialog.askdirectory(parent=self)
        if choice:
            self.set(choice)
            self._changed()

    def _hash_file(self):
        path = self.get().strip()
        if not os.path.isfile(path):
            messagebox.showwarning(
                '计算哈希', '镜像路径不存在,无法计算:\n%s' % path, parent=self)
            return
        with open(path, 'rb') as handle:
            self.set(hashlib.sha256(handle.read()).hexdigest())

    # -- value / lock ---------------------------------------------------------

    def get(self):
        if self._multiline:
            return self.input.get('1.0', 'end').rstrip('\n')
        if self._bool_literals:
            return self._bool_literals[0] if self.variable.get() \
                else self._bool_literals[1]
        return self.variable.get()

    def set(self, value):
        if self._multiline:
            self.input.delete('1.0', 'end')
            self.input.insert('1.0', value)
        elif self._bool_literals:
            self.variable.set(value != self._bool_literals[1])
        else:
            self.variable.set(value)

    def set_locked(self, locked, forced_value=None, badge='🔒 代码强制'):
        state = 'disabled' if locked else 'normal'
        for child in self.winfo_children():
            self._apply_state(child, state)
        if locked and forced_value is not None:
            self.set(forced_value)
        if self._lock_badge is not None:
            self._lock_badge.destroy()
            self._lock_badge = None
        if locked:
            self._lock_badge = ttk.Label(self, text=badge,
                                          style='Locked.TLabel')
            self._lock_badge.grid(row=0, column=2, sticky='w', padx=(6, 0))

    def _apply_state(self, widget, state):
        try:
            widget.configure(state=state)
        except tk.TclError:
            try:
                if state == 'disabled':
                    widget.state(['disabled'])
                else:
                    widget.state(['!disabled'])
            except (tk.TclError, AttributeError):
                pass
        for child in widget.winfo_children():
            self._apply_state(child, state)


def _spans_full_row(field):
    return field.wtype in (schema.T_TEXT, schema.T_PATH_FILE,
                           schema.T_PATH_DIR, schema.T_HEX64) or \
        field.key.lower() == 'listeners'


def build_group_frame(parent, title, fields, getter, on_change, on_focus,
                      registry=None, section_name='', columns=1,
                      label_width=12):
    """Render one titled group of FieldWidgets; returns the frame."""
    box = ttk.LabelFrame(parent, text=title)
    columns = max(1, int(columns))
    for column in range(columns):
        box.columnconfigure(column, weight=1, uniform='field-column')
    row = 0
    column = 0
    for field in fields:
        full_row = columns > 1 and _spans_full_row(field)
        if full_row and column:
            row += 1
            column = 0
        widget = FieldWidget(box, field, value=getter(field.key),
                             on_change=on_change, on_focus=on_focus,
                             label_width=label_width)
        widget.grid(row=row, column=0 if full_row else column,
                    columnspan=columns if full_row else 1,
                    sticky='we', padx=6, pady=0)
        if registry is not None:
            registry[(section_name, field.key.lower())] = widget
        if full_row:
            row += 1
            column = 0
        else:
            column += 1
            if column >= columns:
                row += 1
                column = 0
    return box
