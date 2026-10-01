"""Export real same-input GUI/core calls while retaining existing pytest assertions."""
from __future__ import annotations
import argparse, hashlib, json, socket, sys
from collections.abc import Mapping
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
def digest(b):return hashlib.sha256(b).hexdigest()
def plain(v):
    if v is None or isinstance(v,(str,int,float,bool)):return v
    if isinstance(v,Mapping):return {str(k):plain(x) for k,x in v.items()}
    if isinstance(v,(tuple,list,set,frozenset)):return [plain(x) for x in v]
    return plain(vars(v)) if hasattr(v,'__dict__') else str(v)
class Export:
    def __init__(self,out):self.out=out;self.current=None;self.rows=[];self.patches=[]
    def pytest_sessionstart(self,session):
        from fakenet.gui.configmodel import ConfigModel
        from fakenet.gui import validator
        from fakenet.fakenet import Fakenet
        from fakenet.diverters.egresspolicy import EgressPolicy
        def patch(obj,name,replacement):
            self.patches.append((obj,name,obj.__dict__[name]));setattr(obj,name,replacement)
        validate=validator.validate
        def checked(model,*a,**kw):
            count=[];originals={n:getattr(socket,n) for n in ['getaddrinfo','gethostbyname','gethostbyname_ex']}
            def forbidden(*a,**kw):count.append(plain(a));raise AssertionError('GUI static validator attempted DNS')
            for n in originals:setattr(socket,n,forbidden)
            try:value=validate(model,*a,**kw)
            finally:
                for n,fn in originals.items():setattr(socket,n,fn)
            self.event('GUI.validate',{'issues':plain(value),'dns_calls':count,'field':(model.section('Diverter').get('ExternalAllowedIPv4Rules') if model.section('Diverter') else None)});return value
        patch(validator,'validate',checked)
        render=ConfigModel.render
        def rendered(model,*a,**kw):
            value=render(model,*a,**kw);self.bytes('render',value.encode('utf-8'));return value
        patch(ConfigModel,'render',rendered)
        save=ConfigModel.save
        def saved(model,path,*a,**kw):
            v=save(model,path,*a,**kw);self.bytes('saved',Path(path).read_bytes());return v
        patch(ConfigModel,'save',saved)
        load=ConfigModel.load
        def loaded(cls,path,*a,**kw):
            model=load(path,*a,**kw);self.event('ConfigModel.load',{'path':str(path),'field':(model.section('Diverter').get('ExternalAllowedIPv4Rules') if model.section('Diverter') else None)});return model
        patch(ConfigModel,'load',classmethod(loaded))
        parse=Fakenet.parse_config
        def parsed(obj,path,*a,**kw):
            v=parse(obj,path,*a,**kw);self.event('Fakenet.parse_config',{'diverter_config':plain(obj.diverter_config)});return v
        patch(Fakenet,'parse_config',parsed)
        initialize=EgressPolicy.__init__
        def policy(obj,*a,**kw):
            try:v=initialize(obj,*a,**kw)
            except Exception as e:self.event('EgressPolicy.reject',{'error':type(e).__name__,'message':str(e)});raise
            self.event('EgressPolicy.accept',{'normalized_rules':plain(getattr(obj,'reviewed_ipv4_rules',[])),'rule_ids':plain(getattr(obj,'reviewed_ipv4_rule_ids',{})),'match_index':plain(getattr(obj,'_reviewed_match_index',{})),'config_sha256':getattr(obj,'reviewed_ipv4_config_sha256',None)});return v
        patch(EgressPolicy,'__init__',policy)
    def pytest_runtest_setup(self,item):
        params=plain(getattr(getattr(item,'callspec',None),'params',{}));self.current={'nodeid':item.nodeid,'params':params,'events':[],'outcomes':[]};self.rows.append(self.current)
        if 'text' in params:
            text=params['text'];self.current['field_presence']='absent' if text is None else 'present';self.bytes('input-field',b'' if text is None else text.encode('utf-8'))
    def event(self,name,value):
        if self.current is not None:self.current['events'].append({'event':name,'value':value})
    def bytes(self,label,data):
        if self.current is None:return
        directory=self.out/('case-%04d'%len(self.rows));directory.mkdir(exist_ok=True);name='%s-%03d.raw'%(label,len(self.current['events']));p=directory/name;p.write_bytes(data);self.event(label+'.bytes',{'path':str(p.relative_to(self.out)),'size':len(data),'sha256':digest(data)})
    def pytest_runtest_logreport(self,report):
        if self.current is not None and self.current['nodeid']==report.nodeid:self.current['outcomes'].append({'phase':report.when,'outcome':report.outcome,'longrepr':str(report.longrepr) if report.failed else None})
    def pytest_sessionfinish(self,session,exitstatus):
        for obj,name,original in reversed(self.patches):setattr(obj,name,original)
        payload={'schema':'fakenet.GUI.same-input-export.v1','platform':sys.platform,'python':sys.version,'pytest_exit':exitstatus,'scope':'real original test assertions and calls; exporter only observes/forbids GUI DNS, no acceptance waiver. Network runtime substitutions retain originaltestnature.','cases':self.rows};(self.out/'matrix.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf-8')
def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a,args=p.parse_known_args();a.output.mkdir(parents=True,exist_ok=False)
    import pytest
    return pytest.main(['-q','-rs','--junitxml='+str(a.output/'pytest.xml')]+args,plugins=[Export(a.output)])
if __name__=='__main__':raise SystemExit(main())
