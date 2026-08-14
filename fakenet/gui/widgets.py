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
                 on_focus=None):
        ttk.Frame.__init__(self, parent)
        self.field = field
        self.on_change = on_change
        self.on_focus = on_focus
        self._lock_badge = None

        self.columnconfigure(1, weight=1)
        title = '%s:' % field.label + (' (仅保真)' if field.dead else '')
        self.label = ttk.Label(self, text=title)
        self.label.grid(row=0, column=0, sticky='ne', padx=(0, 6), pady=2)

        wtype = field.wtype
        if wtype in (schema.T_BOOL_YESNO, schema.T_BOOL_TRUEFALSE):
            values = (('Yes', 'No') if wtype == schema.T_BOOL_YESNO
                      else ('True', 'False'))
            self.variable = tk.StringVar(
                value=value if value in values else values[0])
            self.input = ttk.Combobox(self, textvariable=self.variable,
                                      values=values, state='readonly',
                                      width=8)
            self.input.bind('<<ComboboxSelected>>', self._changed)
            self.input.grid(row=0, column=1, sticky='w', pady=2)
        elif wtype in (schema.T_ENUM, schema.T_IPV4_OR_ENUM):
            values = list(field.enum or ())
            if wtype == schema.T_IPV4_OR_ENUM:
                values = [''] + [v for v in values if v]
            self.variable = tk.StringVar(value=value)
            self.input = ttk.Combobox(self, textvariable=self.variable,
                                      values=values, width=36)
            self.input.bind('<<ComboboxSelected>>', self._changed)
            self.input.bind('<FocusOut>', self._changed)
            self.input.grid(row=0, column=1, sticky='we', pady=2)
        elif wtype == schema.T_TEXT:
            self.variable = None
            self.input = tk.Text(self, height=3, width=48, wrap='word')
            self.input.insert('1.0', value)
            self.input.bind('<FocusOut>', self._changed)
            self.input.grid(row=0, column=1, sticky='we', pady=2)
        elif wtype in (schema.T_PATH_FILE, schema.T_PATH_DIR):
            box = ttk.Frame(self)
            box.grid(row=0, column=1, sticky='we', pady=2)
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
            self.input = ttk.Entry(self, textvariable=self.variable,
                                   width=48)
            self.input.bind('<FocusOut>', self._changed)
            self.input.grid(row=0, column=1, sticky='we', pady=2)

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
        if self.field.wtype == schema.T_TEXT:
            return self.input.get('1.0', 'end').rstrip('\n')
        return self.variable.get()

    def set(self, value):
        if self.field.wtype == schema.T_TEXT:
            self.input.delete('1.0', 'end')
            self.input.insert('1.0', value)
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
            self._lock_badge = ttk.Label(self, text=badge, foreground='#a00')
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


def build_group_frame(parent, title, fields, getter, on_change, on_focus,
                      registry=None, section_name=''):
    """Render one titled group of FieldWidgets; returns the frame."""
    box = ttk.LabelFrame(parent, text=title)
    for row, field in enumerate(fields):
        widget = FieldWidget(box, field, value=getter(field.key),
                             on_change=on_change, on_focus=on_focus)
        widget.grid(row=row, column=0, sticky='we', padx=6, pady=1)
        if registry is not None:
            registry[(section_name, field.key.lower())] = widget
    return box
