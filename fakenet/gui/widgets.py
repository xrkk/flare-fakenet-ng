# -*- coding: utf-8 -*-
"""Native field widgets for fakenet-GUI (plan v1.13 §12.17).

One FieldWidget per schema.Field: label, type-specific input, lock badge,
focus-driven hint callback.  Locked widgets render read-only with a
'代码强制' badge; a forced value can be applied while locking.
"""

import tkinter as tk
from tkinter import ttk, filedialog, simpledialog

from fakenet.gui import schema


class _HoverHelp(object):
    """One delayed, non-focus-stealing tooltip shared by a field tree."""

    DELAY_MS = 450

    def __init__(self, owner, text, on_hover=None, status_text=None):
        self.owner = owner
        self.text = text
        self.on_hover = on_hover
        self.status_text = status_text or text
        self.window = None
        self._job = None
        self.bind_tree(owner)
        owner.bind('<Destroy>', self._destroy, add='+')

    def bind_tree(self, widget):
        widget.bind('<Enter>', self._enter, add='+')
        widget.bind('<Leave>', self._leave, add='+')
        widget.bind('<ButtonPress>', self._leave, add='+')
        for child in widget.winfo_children():
            self.bind_tree(child)

    def _enter(self, _event=None):
        self._cancel()
        self._hide()
        if self.on_hover:
            self.on_hover(self.status_text)
        if self.text:
            self._job = self.owner.after(self.DELAY_MS, self._show)

    def _leave(self, _event=None):
        self._cancel()
        self._hide()

    def _cancel(self):
        if self._job is not None:
            try:
                self.owner.after_cancel(self._job)
            except tk.TclError:
                pass
            self._job = None

    def _show(self):
        self._cancel()
        if self.window is not None or not self.owner.winfo_exists():
            return
        window = tk.Toplevel(self.owner)
        window.wm_overrideredirect(True)
        try:
            window.wm_attributes('-topmost', True)
        except tk.TclError:
            pass
        tk.Label(
            window, text=self.text, justify='left', anchor='w',
            background='#FFFFE1', foreground='#1F2937',
            relief='solid', borderwidth=1, padx=8, pady=6,
            wraplength=420, font=('Microsoft YaHei UI', 9)).pack()
        window.update_idletasks()

        x = self.owner.winfo_pointerx() + 14
        y = self.owner.winfo_pointery() + 18
        left = self.owner.winfo_vrootx() + 8
        top = self.owner.winfo_vrooty() + 8
        right = (self.owner.winfo_vrootx() +
                 self.owner.winfo_vrootwidth() - 8)
        bottom = (self.owner.winfo_vrooty() +
                  self.owner.winfo_vrootheight() - 8)
        x = max(left, min(x, right - window.winfo_reqwidth()))
        y = max(top, min(y, bottom - window.winfo_reqheight()))
        window.wm_geometry('%+d%+d' % (x, y))
        self.window = window

    def _hide(self):
        if self.window is not None:
            try:
                self.window.destroy()
            except tk.TclError:
                pass
            self.window = None

    def _destroy(self, event=None):
        if event is None or event.widget is self.owner:
            self._cancel()
            self._hide()


def attach_tooltip(owner, text, on_hover=None, status_text=None):
    """Attach hover help to an existing widget tree and keep it alive."""
    tooltip = _HoverHelp(owner, text, on_hover, status_text)
    owner._hover_help = tooltip
    return tooltip


class FieldWidget(ttk.Frame):

    def __init__(self, parent, field, value='', on_change=None,
                 on_focus=None, label_width=12):
        ttk.Frame.__init__(self, parent)
        self.field = field
        self.on_change = on_change
        self.on_focus = on_focus
        self._lock_badge = None
        self._error_label = None
        self._multiline = False
        self._bool_literals = None

        self.columnconfigure(1, weight=1)
        title = '%s:' % field.label + ('（仅保真）' if field.dead else '')
        self.label = ttk.Label(
            self, text=title, width=label_width, anchor='e',
            justify='right', wraplength=max(80, label_width * 8))
        self.label.grid(row=0, column=0, sticky='ne', padx=(0, 6), pady=1)

        wtype = field.wtype
        if wtype in (schema.T_BOOL_YESNO, schema.T_BOOL_TRUEFALSE,
                     schema.T_BOOL_POLICY):
            if wtype == schema.T_BOOL_YESNO:
                values = ('Yes', 'No')
            elif wtype == schema.T_BOOL_TRUEFALSE:
                values = ('True', 'False')
            else:
                values = (schema.EGRESS_POLICY_ENABLED,
                          schema.EGRESS_POLICY_DISABLED)
            self._bool_literals = values
            checked = value == values[0] if wtype == schema.T_BOOL_POLICY \
                else value != values[1]
            self.variable = tk.BooleanVar(value=checked)
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

        for widget in (self.input, self.label):
            widget.bind('<FocusIn>', self._focused)
        self.tooltip = attach_tooltip(
            self, '%s\n%s' % (field.label, field.hint),
            on_focus, field.hint)
        self._last_reported = self.get()

    # -- events --------------------------------------------------------------

    def _focused(self, _event=None):
        if self.on_focus and self.field.hint:
            self.on_focus(self.field.hint)

    def _changed(self, _event=None):
        value = self.get()
        if value == self._last_reported:
            return
        self._last_reported = value
        if self.on_change:
            self.on_change(self.field.key, value)

    def _browse(self):
        if self.field.wtype == schema.T_PATH_FILE:
            choice = filedialog.askopenfilename(parent=self)
        else:
            choice = filedialog.askdirectory(parent=self)
        if choice:
            # Selecting the same file is still an explicit request.  The
            # process-image field uses this forced notification to re-hash.
            self.set(choice, notify=True, force=True)

    # -- value / lock ---------------------------------------------------------

    def get(self):
        if self._multiline:
            return self.input.get('1.0', 'end').rstrip('\n')
        if self._bool_literals:
            return self._bool_literals[0] if self.variable.get() \
                else self._bool_literals[1]
        return self.variable.get()

    def set(self, value, notify=False, force=False):
        previous = self.get()
        if self._multiline:
            self.input.delete('1.0', 'end')
            self.input.insert('1.0', value)
        elif self._bool_literals:
            checked = value == self._bool_literals[0] \
                if self.field.wtype == schema.T_BOOL_POLICY \
                else value != self._bool_literals[1]
            self.variable.set(checked)
        else:
            self.variable.set(value)
        current = self.get()
        self._last_reported = current
        if notify and self.on_change and (force or current != previous):
            self.on_change(self.field.key, current)

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
            self.tooltip.bind_tree(self._lock_badge)

    def set_error(self, message=''):
        """Show one compact inline error without changing the field value."""
        if self._error_label is not None:
            self._error_label.destroy()
            self._error_label = None
        if message:
            self._error_label = ttk.Label(
                self, text=message, style='InlineError.TLabel',
                justify='left', wraplength=440)
            self._error_label.grid(row=1, column=1, columnspan=2,
                                   sticky='w', pady=(0, 2))
            self.tooltip.bind_tree(self._error_label)

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


class CsvListFieldWidget(ttk.Frame):
    """Compact native editor for a comma-separated list of strings."""

    def __init__(self, parent, field, value='', on_change=None,
                 on_focus=None, height=3):
        ttk.Frame.__init__(self, parent)
        self.field = field
        self.on_change = on_change
        self.on_focus = on_focus
        self._items = []
        self._locked = False
        self._error_label = None
        self.columnconfigure(0, weight=1)
        self.label = ttk.Label(self, text='%s:' % field.label,
                               font=('', 9, 'bold'))
        self.label.grid(row=0, column=0, sticky='w')
        body = ttk.Frame(self)
        body.grid(row=1, column=0, sticky='nsew', pady=(2, 0))
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        self.input = ttk.Treeview(
            body, columns=('value',), show='headings', height=height,
            selectmode='browse')
        self.input.heading('value', text='域名')
        self.input.column('value', width=280, stretch=True)
        self.input.grid(row=0, column=0, sticky='nsew')
        bar = ttk.Scrollbar(body, orient='vertical', command=self.input.yview)
        bar.grid(row=0, column=1, sticky='ns')
        self.input.configure(yscrollcommand=bar.set)
        actions = ttk.Frame(body)
        actions.grid(row=0, column=2, sticky='n', padx=(5, 0))
        self._buttons = []
        for text, command in (('添加…', self._add), ('编辑…', self._edit),
                              ('删除', self._delete)):
            button = ttk.Button(actions, text=text, width=7,
                                command=command)
            button.pack(fill='x', pady=(0, 3))
            self._buttons.append(button)
        self.input.bind('<Double-1>', lambda _e: self._edit())
        self.input.bind('<FocusIn>', self._focused)
        self.label.bind('<FocusIn>', self._focused)
        self.tooltip = attach_tooltip(
            self, '%s\n%s' % (field.label, field.hint),
            on_focus, field.hint)
        self.set(value)

    def _focused(self, _event=None):
        if self.on_focus and self.field.hint:
            self.on_focus(self.field.hint)

    def _prompt(self, title, initial=''):
        return simpledialog.askstring(
            title, '域名（不含协议、端口、路径或通配符）:',
            initialvalue=initial, parent=self)

    def _add(self):
        value = self._prompt('添加放行域名')
        if value is None:
            return
        value = value.strip()
        if value and value.lower() not in {item.lower() for item in self._items}:
            self._items.append(value)
            self._render()
            self._changed()

    def _edit(self):
        selected = self.input.selection()
        if not selected:
            return
        index = self.input.index(selected[0])
        value = self._prompt('编辑放行域名', self._items[index])
        if value is None:
            return
        value = value.strip()
        if not value:
            return
        self._items[index] = value
        self._render(select=index)
        self._changed()

    def _delete(self):
        selected = self.input.selection()
        if not selected:
            return
        del self._items[self.input.index(selected[0])]
        self._render()
        self._changed()

    def _render(self, select=None):
        self.input.delete(*self.input.get_children())
        for item in self._items:
            self.input.insert('', 'end', values=(item,))
        if select is not None and select < len(self._items):
            iid = self.input.get_children()[select]
            self.input.selection_set(iid)

    def _changed(self):
        if self.on_change:
            self.on_change(self.field.key, self.get())

    def get(self):
        return ', '.join(self._items)

    def set(self, value, notify=False, force=False):
        previous = self.get()
        self._items = [item.strip() for item in str(value or '').split(',')
                       if item.strip()]
        self._render()
        if notify and self.on_change and (force or self.get() != previous):
            self._changed()

    def set_locked(self, locked, forced_value=None,
                   badge='系统或策略约束'):
        self._locked = bool(locked)
        if forced_value is not None:
            self.set(forced_value)
        state = ['disabled'] if locked else ['!disabled']
        for button in self._buttons:
            button.state(state)
        self.input.state(state)

    def set_error(self, message=''):
        if self._error_label is not None:
            self._error_label.destroy()
            self._error_label = None
        if message:
            self._error_label = ttk.Label(
                self, text=message, style='InlineError.TLabel',
                justify='left', wraplength=440)
            self._error_label.grid(row=2, column=0, sticky='w', pady=(2, 0))
            self.tooltip.bind_tree(self._error_label)


class IPv4RulesFieldWidget(ttk.Frame):
    """Three-column editor for ExternalAllowedIPv4Rules."""

    def __init__(self, parent, field, value='', on_change=None,
                 on_focus=None, height=4):
        ttk.Frame.__init__(self, parent)
        self.field = field
        self.on_change = on_change
        self.on_focus = on_focus
        self._rules = []
        self._error_label = None
        self.columnconfigure(0, weight=1)
        self.label = ttk.Label(self, text='%s:' % field.label,
                               font=('', 9, 'bold'))
        self.label.grid(row=0, column=0, sticky='w')
        body = ttk.Frame(self)
        body.grid(row=1, column=0, sticky='nsew', pady=(2, 0))
        body.columnconfigure(0, weight=1)
        self.input = ttk.Treeview(
            body, columns=('protocol', 'ipv4', 'port'), show='headings',
            height=height, selectmode='browse')
        for key, title, width in (('protocol', '协议', 70),
                                  ('ipv4', '公网 IPv4', 190),
                                  ('port', '端口', 90)):
            self.input.heading(key, text=title)
            self.input.column(key, width=width, stretch=(key == 'ipv4'))
        self.input.grid(row=0, column=0, sticky='nsew')
        ybar = ttk.Scrollbar(body, orient='vertical', command=self.input.yview)
        ybar.grid(row=0, column=1, sticky='ns')
        self.input.configure(yscrollcommand=ybar.set)
        actions = ttk.Frame(body)
        actions.grid(row=0, column=2, sticky='n', padx=(5, 0))
        self._buttons = []
        for text, command in (('添加…', self._add), ('编辑…', self._edit),
                              ('删除', self._delete)):
            button = ttk.Button(actions, text=text, width=7,
                                command=command)
            button.pack(fill='x', pady=(0, 3))
            self._buttons.append(button)
        self.input.bind('<Double-1>', lambda _e: self._edit())
        self.input.bind('<FocusIn>', self._focused)
        self.tooltip = attach_tooltip(
            self, '%s\n%s' % (field.label, field.hint),
            on_focus, field.hint)
        self.set(value)

    def _focused(self, _event=None):
        if self.on_focus and self.field.hint:
            self.on_focus(self.field.hint)

    def _prompt_rule(self, title, initial=None):
        initial = initial or ('TCP', '', '443')
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.transient(self.winfo_toplevel())
        dialog.resizable(False, False)
        result = []
        protocol = tk.StringVar(value=initial[0])
        ipv4 = tk.StringVar(value=initial[1])
        port = tk.StringVar(value=initial[2])
        for row, label in enumerate(('协议:', '公网 IPv4:', '端口:')):
            ttk.Label(dialog, text=label).grid(
                row=row, column=0, padx=(10, 5), pady=4, sticky='e')
        protocol_box = ttk.Combobox(
            dialog, textvariable=protocol, values=('TCP', 'UDP'),
            state='readonly', width=8)
        protocol_box.grid(row=0, column=1, padx=(0, 10), pady=(10, 4),
                          sticky='w')
        ip_entry = ttk.Entry(dialog, textvariable=ipv4, width=24)
        ip_entry.grid(row=1, column=1, padx=(0, 10), pady=4, sticky='w')
        ttk.Entry(dialog, textvariable=port, width=12).grid(
            row=2, column=1, padx=(0, 10), pady=4, sticky='w')

        def accept():
            values = (protocol.get().strip().upper(), ipv4.get().strip(),
                      port.get().strip())
            if all(values):
                result.append(values)
                dialog.destroy()

        buttons = ttk.Frame(dialog)
        buttons.grid(row=3, column=0, columnspan=2, pady=(6, 10))
        ttk.Button(buttons, text='确定', command=accept).pack(side='left')
        ttk.Button(buttons, text='取消', command=dialog.destroy).pack(
            side='left', padx=(6, 0))
        dialog.bind('<Return>', lambda _e: accept())
        dialog.bind('<Escape>', lambda _e: dialog.destroy())
        dialog.grab_set()
        ip_entry.focus_set()
        dialog.wait_window()
        return result[0] if result else None

    def _add(self):
        rule = self._prompt_rule('添加公网 IPv4 放行规则')
        if rule:
            self._rules.append(rule)
            self._render(select=len(self._rules) - 1)
            self._changed()

    def _edit(self):
        selected = self.input.selection()
        if not selected:
            return
        index = self.input.index(selected[0])
        rule = self._prompt_rule('编辑公网 IPv4 放行规则',
                                 self._rules[index])
        if rule:
            self._rules[index] = rule
            self._render(select=index)
            self._changed()

    def _delete(self):
        selected = self.input.selection()
        if not selected:
            return
        del self._rules[self.input.index(selected[0])]
        self._render()
        self._changed()

    def _render(self, select=None):
        self.input.delete(*self.input.get_children())
        for rule in self._rules:
            self.input.insert('', 'end', values=rule)
        if select is not None and select < len(self._rules):
            iid = self.input.get_children()[select]
            self.input.selection_set(iid)

    def _changed(self):
        if self.on_change:
            self.on_change(self.field.key, self.get())

    def get(self):
        return ', '.join('%s/%s/%s' % rule for rule in self._rules)

    def set(self, value, notify=False, force=False):
        previous = self.get()
        rules = []
        for item in str(value or '').split(','):
            item = item.strip()
            parts = tuple(part.strip() for part in item.split('/'))
            if item and len(parts) == 3:
                rules.append(parts)
        self._rules = rules
        self._render()
        if notify and self.on_change and (force or self.get() != previous):
            self._changed()

    def set_locked(self, locked, forced_value=None, badge=''):
        if forced_value is not None:
            self.set(forced_value)
        state = ['disabled'] if locked else ['!disabled']
        for button in self._buttons:
            button.state(state)
        self.input.state(state)

    def set_error(self, message=''):
        if self._error_label is not None:
            self._error_label.destroy()
            self._error_label = None
        if message:
            self._error_label = ttk.Label(
                self, text=message, style='InlineError.TLabel',
                justify='left', wraplength=500)
            self._error_label.grid(row=2, column=0, sticky='w', pady=(2, 0))
            self.tooltip.bind_tree(self._error_label)


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
