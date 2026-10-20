import importlib.util
from pathlib import Path
import pytest
P=Path(__file__).resolve().parents[2]/'tools/fakenet_egress_fixture.py'
spec=importlib.util.spec_from_file_location('fixture_pid_repro',P);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ACTUAL=['/usr/bin/vmnet-natd','-s','6','-m','/etc/vmware/vmnet8/nat.mac','-c','/etc/vmware/vmnet8/nat/nat.conf']
def test_real_linux_vmware_argv_accepts_fixed_verified_pidfile(monkeypatch):
 monkeypatch.setattr(m,'proc',lambda pid:{'pid':3730,'birth_ticks':2179,'comm':'vmnet-natd','argv':ACTUAL})
 monkeypatch.setattr(m,'read_root',lambda p:3730)
 got=m.current_nat({'natd_pid':3730,'natd_birth_ticks':2179})
 assert got['pid']==3730

@pytest.mark.parametrize('file_pid',[3731,True,'3730',None])
def test_wrong_or_untyped_pidfile_refused(monkeypatch,file_pid):
 monkeypatch.setattr(m,'proc',lambda pid:{'pid':3730,'birth_ticks':2179,'comm':'vmnet-natd','argv':ACTUAL})
 monkeypatch.setattr(m,'read_root',lambda path:file_pid)
 with pytest.raises(RuntimeError,match='pidfile identity'):m.current_nat({'natd_pid':3730,'natd_birth_ticks':2179})

@pytest.mark.parametrize('birth,argv',[(2180,ACTUAL),(2179,ACTUAL[:-1]+['/etc/vmware/vmnet1/nat/nat.conf']),(2179,ACTUAL+['-p','/tmp/forged.pid'])])
def test_birth_or_interface_or_extra_pid_path_rejected_before_file(monkeypatch,birth,argv):
 monkeypatch.setattr(m,'proc',lambda pid:{'pid':3730,'birth_ticks':birth,'comm':'vmnet-natd','argv':argv})
 monkeypatch.setattr(m,'read_root',lambda path:pytest.fail('file read before kernel and argv identity'))
 with pytest.raises(RuntimeError):m.current_nat({'natd_pid':3730,'natd_birth_ticks':2179})

def test_only_secure_canonical_runtime_file_is_consumed(monkeypatch):
 monkeypatch.setattr(m,'proc',lambda pid:{'pid':3730,'birth_ticks':2179,'comm':'vmnet-natd','argv':ACTUAL})
 def read(path):
  assert path=='/run/vmnet-natd-8.pid'
  raise RuntimeError('unsafe root object')
 monkeypatch.setattr(m,'read_root',read)
 with pytest.raises(RuntimeError,match='unsafe root object'):m.current_nat({'natd_pid':3730,'natd_birth_ticks':2179})
