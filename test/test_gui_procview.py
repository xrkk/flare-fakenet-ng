# -*- coding: utf-8 -*-
"""Host-side checks for the process network view.

Plan 2026.08.21-01 I1/I9.1: fixtures use REAL log line formats — the file
format (two bracket headers + pid=/thread= prefix, fakenet.py:94-96) and the
console format (single bracket, no prefix, fakenet.py:106-107). The v1.32
fixtures used a fabricated format that no logger produces and masked the
regex-mismatch defect this round fixes.
"""

import tkinter as tk

from fakenet.gui import procview

# Real file-format line (taken from the v31 field export phase1.log).
LINE_FILE_FORMAT = (
    "08/18/26 08:16:10 PM [INFO    ] [          Diverter] pid=2664 "
    "thread=WinDivert PROCESS_FLOW disposition=DIVERT_FAKE domain=- "
    "dport=5353 dst=224.0.0.251 pid=2240 process=svchost.exe proto=UDP "
    "sport=5353 src=192.168.204.166")
# Real console-format line (per the console formatter: single bracket and
# no pid=/thread= prefix; the flow-level pid lives in the message fields).
LINE_CONSOLE_FORMAT = (
    "08/18/26 08:16:10 PM [          Diverter] PROCESS_FLOW "
    "disposition=DROP_EXTERNAL domain=- dport=5355 dst=224.0.0.252 "
    "pid=2240 process=svchost.exe proto=UDP sport=63282 "
    "src=192.168.204.166")
LINE_FILE_SAMPLE = (
    "08/18/26 08:16:26 PM [INFO    ] [          Diverter] pid=3696 "
    "thread=WinDivert PROCESS_FLOW disposition=REDIRECT_TLS_RELAY "
    "domain=api.deepseek.com dport=443 dst=101.71.73.135 pid=7376 "
    "process=msedge.exe proto=TCP sport=49843 src=192.168.204.166")
LINE_SPACED_PROCESS = (
    "08/18/26 08:16:30 PM [INFO    ] [          Diverter] pid=3696 "
    "thread=WinDivert PROCESS_FLOW disposition=DIVERT_FAKE domain=- "
    "dport=80 dst=93.184.216.34 pid=999 process=Internet_Explorer.exe "
    "proto=TCP sport=50001 src=192.168.204.166")
LINE_OTHER_EVENT = (
    "08/20/26 08:48:34 AM [          Diverter] PCAP_DUAL_SUMMARY "
    "raw=packets_20260820_084337.pcap ethernet=x-converted.pcap "
    "raw_count=2875 ethernet_count=2875 rejected_count=0 healthy=True")


def test_parse_process_flow_line_file_format():
    flow = procview.parse_process_flow_line(LINE_FILE_FORMAT)
    assert flow is not None
    assert flow['pid'] == '2240'
    assert flow['process'] == 'svchost.exe'
    assert flow['disposition'] == 'DIVERT_FAKE'
    assert flow['dst'] == '224.0.0.251'
    assert flow['dport'] == '5353'
    assert flow['domain'] == '-'
    assert flow['time'].startswith('08/18/26 08:16:10')


def test_parse_process_flow_line_console_format():
    flow = procview.parse_process_flow_line(LINE_CONSOLE_FORMAT)
    assert flow is not None
    assert flow['pid'] == '2240'
    assert flow['process'] == 'svchost.exe'
    assert flow['disposition'] == 'DROP_EXTERNAL'
    assert flow['dst'] == '224.0.0.252'


def test_parse_process_flow_line_rejects_other_events():
    assert procview.parse_process_flow_line(LINE_OTHER_EVENT) is None
    assert procview.parse_process_flow_line('random text') is None
    assert procview.parse_process_flow_line('') is None


def test_dispositions_list_has_no_removed_sink_verdict():
    assert 'ALLOW_TAKEOVER_SINK' not in procview.DISPOSITIONS
    assert 'DIVERT_FAKE' in procview.DISPOSITIONS


class WindowFixture(object):
    def __enter__(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.geometry('1200x800+100+50')
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


def test_window_groups_flows_by_process_real_formats():
    with WindowFixture() as view:
        view.feed('\n'.join(
            [LINE_FILE_FORMAT, LINE_CONSOLE_FORMAT, LINE_FILE_SAMPLE]) + '\n')
        processes = view.tree.get_children('')
        assert len(processes) == 2
        labels = [view.tree.item(node, 'text') for node in processes]
        assert any('[2240] svchost.exe (2)' in label for label in labels)
        assert any('[7376] msedge.exe (1)' in label for label in labels)
        flows = _flows_of(view)
        assert len(flows) == 3
        targets = {row[0] for row in flows}
        assert '224.0.0.251:5353' in targets
        assert '101.71.73.135:443' in targets


def test_window_filters_by_name_pid_and_disposition():
    with WindowFixture() as view:
        view.feed('\n'.join(
            [LINE_FILE_FORMAT, LINE_CONSOLE_FORMAT, LINE_FILE_SAMPLE]) + '\n')

        view.name_var.set('svchost')
        view._filters_changed()
        assert len(_flows_of(view)) == 2

        view.name_var.set('msedge')
        view._filters_changed()
        flows = _flows_of(view)
        assert len(flows) == 1
        assert flows[0][2] == 'REDIRECT_TLS_RELAY'

        view.name_var.set('')
        view.pid_var.set('2240')
        view._filters_changed()
        assert len(_flows_of(view)) == 2

        view.pid_var.set('')
        view.disp_var.set('DIVERT_FAKE')
        view._filters_changed()
        flows = _flows_of(view)
        assert len(flows) == 1
        assert flows[0][0] == '224.0.0.251:5353'

        view.disp_var.set('全部')
        view._clear()
        assert _flows_of(view) == []


def test_window_name_filter_matches_spaces_as_underscores():
    with WindowFixture() as view:
        view.feed(LINE_SPACED_PROCESS + '\n')
        assert len(_flows_of(view)) == 1
        view.name_var.set('Internet Explorer')
        view._filters_changed()
        assert len(_flows_of(view)) == 1
        view.name_var.set('internet_explorer')
        view._filters_changed()
        assert len(_flows_of(view)) == 1
        view.name_var.set('chrome')
        view._filters_changed()
        assert _flows_of(view) == []


def test_window_pause_blocks_ingest_and_clear_resets():
    with WindowFixture() as view:
        view.feed(LINE_FILE_FORMAT + '\n')
        assert len(_flows_of(view)) == 1
        view.paused = True
        view.feed(LINE_FILE_SAMPLE + '\n')
        assert len(_flows_of(view)) == 1


def test_center_over_parent_clamps_to_screen():
    class FakeParent(object):
        def __init__(self, x, y, w, h, sw, sh):
            self._geo = (x, y, w, h, sw, sh)

        def winfo_x(self):
            return self._geo[0]

        def winfo_y(self):
            return self._geo[1]

        def winfo_width(self):
            return self._geo[2]

        def winfo_height(self):
            return self._geo[3]

        def winfo_screenwidth(self):
            return self._geo[4]

        def winfo_screenheight(self):
            return self._geo[5]

    centered = procview.ProcessFlowWindow._center_over_parent(
        FakeParent(100, 50, 1200, 800, 1920, 1080), 980, 560)
    assert centered == '+%d+%d' % (100 + (1200 - 980) // 2,
                                    50 + (800 - 560) // 2)
    clamped = procview.ProcessFlowWindow._center_over_parent(
        FakeParent(1900, 900, 1200, 800, 1920, 1080), 980, 560)
    x, y = [int(part) for part in clamped.lstrip('+').split('+')]
    assert x == 1920 - 980
    assert y == 1080 - 560
    negative = procview.ProcessFlowWindow._center_over_parent(
        FakeParent(-200, -400, 1200, 800, 1920, 1080), 980, 560)
    assert negative.startswith('+0+')
