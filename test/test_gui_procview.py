# -*- coding: utf-8 -*-
"""Host-side checks for the process network view (plan v1.32 12.32.2)."""

import tkinter as tk

from fakenet.gui import procview

LINE_DIVERT = (
    "08/18/26 12:00:01 PM [INFO] Diverter PROCESS_FLOW "
    "disposition=DIVERT_FAKE domain=- dport=80 dst=93.184.216.34 "
    "pid=4242 process=malware.exe proto=TCP sport=50001 src=10.0.0.5")
LINE_RELAY = (
    "08/18/26 12:00:05 PM [INFO] Diverter PROCESS_FLOW "
    "disposition=REDIRECT_TLS_RELAY domain=api.deepseek.com dport=443 "
    "dst=101.71.73.135 pid=4242 process=malware.exe proto=TCP "
    "sport=50002 src=10.0.0.5")
LINE_BROWSER = (
    "08/18/26 12:00:09 PM [INFO] Diverter PROCESS_FLOW "
    "disposition=ALLOW_TAKEOVER_SINK domain=- dport=443 "
    "dst=192.168.204.1 pid=88 process=chrome.exe proto=TCP "
    "sport=50003 src=10.0.0.5")
LINE_DROP = (
    "08/18/26 12:00:10 PM [INFO] Diverter DROP_EXTERNAL "
    "reason=no_authorized_route original_ip=1.2.3.4 original_port=80")


def test_parse_process_flow_line_fields():
    flow = procview.parse_process_flow_line(LINE_DIVERT)
    assert flow is not None
    assert flow['pid'] == '4242'
    assert flow['process'] == 'malware.exe'
    assert flow['disposition'] == 'DIVERT_FAKE'
    assert flow['dst'] == '93.184.216.34'
    assert flow['dport'] == '80'
    assert flow['domain'] == '-'
    assert flow['time'].startswith('08/18/26 12:00:01')


def test_parse_process_flow_line_rejects_other_events():
    assert procview.parse_process_flow_line(LINE_DROP) is None
    assert procview.parse_process_flow_line('random text') is None
    assert procview.parse_process_flow_line('') is None


class WindowFixture(object):
    def __enter__(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.view = procview.ProcessFlowWindow(self.root, None)
        return self.view

    def __exit__(self, *_exc):
        try:
            self.view.window.destroy()
        finally:
            self.root.destroy()
        return False


def _flows_of(view):
    rows = []
    for process_node in view.tree.get_children(''):
        for child in view.tree.get_children(process_node):
            rows.append(view.tree.item(child, 'values'))
    return rows


def test_window_groups_flows_by_process():
    with WindowFixture() as view:
        view.feed('\n'.join([LINE_DIVERT, LINE_RELAY, LINE_BROWSER]) + '\n')
        processes = view.tree.get_children('')
        assert len(processes) == 2
        labels = [view.tree.item(node, 'text') for node in processes]
        assert any('[4242] malware.exe (2)' in label for label in labels)
        assert any('[88] chrome.exe (1)' in label for label in labels)
        flows = _flows_of(view)
        assert len(flows) == 3
        targets = {row[0] for row in flows}
        assert '93.184.216.34:80' in targets
        assert '101.71.73.135:443' in targets


def test_window_filters_by_name_pid_and_disposition():
    with WindowFixture() as view:
        view.feed('\n'.join([LINE_DIVERT, LINE_RELAY, LINE_BROWSER]) + '\n')

        view.name_var.set('malware')
        view._filters_changed()
        flows = _flows_of(view)
        assert len(flows) == 2

        view.name_var.set('')
        view.pid_var.set('88')
        view._filters_changed()
        flows = _flows_of(view)
        assert len(flows) == 1
        assert flows[0][2] == 'ALLOW_TAKEOVER_SINK'

        view.pid_var.set('')
        view.disp_var.set('DIVERT_FAKE')
        view._filters_changed()
        flows = _flows_of(view)
        assert len(flows) == 1
        assert flows[0][0] == '93.184.216.34:80'

        view.disp_var.set('全部')
        view._clear()
        assert _flows_of(view) == []


def test_window_pause_blocks_ingest_and_clear_resets():
    with WindowFixture() as view:
        view.feed(LINE_DIVERT + '\n')
        assert len(_flows_of(view)) == 1
        view.paused = True
        view.feed(LINE_BROWSER + '\n')
        assert len(_flows_of(view)) == 1
