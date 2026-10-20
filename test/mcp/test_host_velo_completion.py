import json,sys
from contextlib import asynccontextmanager
from types import SimpleNamespace
import pytest
from fakenet.mcp import host_stdio
@pytest.mark.parametrize('value',[{'operation':'start_artifact_collection','status':'WAITING','flow_id':'F.example'},{'status':'error','error':'not_ready'},{}])
def test_nonterminal_or_missing_business_response_never_proves_roundtrip(monkeypatch,value):
 client=host_stdio.VeloMcpClient({'url':'http://127.0.0.1:9/mcp','tool':'health','allowed_tools':['health'],'arguments':{}})
 monkeypatch.setattr(client,'list_tools',lambda timeout:SimpleNamespace(tools=[SimpleNamespace(name='health')]))
 class Remote:
  async def call_tool(self,*a):return SimpleNamespace(is_error=False,structured_content=value,content=[])
 @asynccontextmanager
 async def transport(*a):yield Remote()
 monkeypatch.setattr(host_stdio,'_sdk_http_client',transport)
 ok,_=client.probe(timeout=1)
 assert ok is not True

@pytest.mark.parametrize('structured,text',[(True,False),(False,True)])
def test_completed_read_only_response_is_preserved(monkeypatch,structured,text):
 value={'operation':'get_flow_status','status':'success','state':'FINISHED','flow_id':'F.example'}
 client=host_stdio.VeloMcpClient({'url':'http://127.0.0.1:9/mcp','tool':'get_flow_status','allowed_tools':['get_flow_status'],'arguments':{'flow_id':'F.example'},'allowed_arguments':['flow_id']})
 monkeypatch.setattr(client,'list_tools',lambda timeout:SimpleNamespace(tools=[SimpleNamespace(name='get_flow_status')]))
 class Remote:
  async def call_tool(self,name,args):
   assert name=='get_flow_status' and args=={'flow_id':'F.example'}
   return SimpleNamespace(is_error=False,structured_content=value if structured else None,content=[SimpleNamespace(text=json.dumps(value))] if text else [])
 @asynccontextmanager
 async def transport(*a):yield Remote()
 monkeypatch.setattr(host_stdio,'_sdk_http_client',transport)
 ok,detail=client.probe(timeout=1)
 assert ok is True and detail['response']==value and len(detail['response_sha256'])==64
