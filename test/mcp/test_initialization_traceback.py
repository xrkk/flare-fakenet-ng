from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
from run_initialization_case import initialization_traceback


FROZEN = '''Traceback (most recent call last):
  File "fakenet/mcp/managed.py", line 295, in child_main
  File "fakenet/fakenet.py", line 242, in start
  File "fakenet/mcp/faultinject.py", line 131, in initialize
RuntimeError: injected managed initialization failure
'''


def test_frozen_traceback_without_source_lines_proves_actual_call_path():
    assert initialization_traceback(FROZEN)
    assert initialization_traceback(FROZEN.replace('/', '\\'))


def test_error_text_without_actual_start_frame_is_not_evidence():
    assert not initialization_traceback(FROZEN.replace('in start', 'in validate_config'))
    assert not initialization_traceback('RuntimeError: injected managed initialization failure')
    assert not initialization_traceback(FROZEN.replace('fakenet/fakenet.py', 'unrelated.py'))
