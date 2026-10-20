"""Existing endpoint auth is referenced, never copied into results or traces."""
import json

import anyio
import pytest

from fakenet.mcp import host_stdio


def test_missing_auth_ref_fails_before_client_creation(monkeypatch):
    monkeypatch.delenv('FN_TEST_AUTH',raising=False)
    called=[]
    monkeypatch.setattr(host_stdio,'Client',lambda *a,**k:called.append(a))
    with pytest.raises(host_stdio.HostFacadeError,match='unavailable'):
        host_stdio._sdk_http_client({'url':'http://127.0.0.1:9/mcp','bearer_token_env':'FN_TEST_AUTH'},1)
    assert called==[]


@pytest.mark.parametrize('reference',[
    {'auth_headers_env':{'Host':'FN_TEST_AUTH'}},
    {'auth_headers_env':{'Authorization':'bad-name'}},
    {'auth_headers_env':{'Authorization':'FN_TEST_AUTH'},'bearer_token_env':'FN_TEST_AUTH'},
])
def test_auth_cannot_override_protocol_or_accept_ambiguous_refs(monkeypatch,reference):
    monkeypatch.setenv('FN_TEST_AUTH','synthetic-secret-for-test')
    with pytest.raises(host_stdio.HostFacadeError):host_stdio._auth_headers(reference)


def test_auth_newlines_refused_and_exception_redacted(monkeypatch):
    spec={'bearer_token_env':'FN_TEST_AUTH'}
    monkeypatch.setenv('FN_TEST_AUTH','unsafe\r\nHeader: x')
    with pytest.raises(host_stdio.HostFacadeError):host_stdio._auth_headers(spec)
    secret='synthetic-secret-for-test'
    monkeypatch.setenv('FN_TEST_AUTH',secret)
    error=RuntimeError('Bearer '+secret+' raw='+secret)
    message=host_stdio._safe_transport_error(error,spec)
    assert secret not in message and '<REDACTED>' in message
    assert spec=={'bearer_token_env':'FN_TEST_AUTH'}


def test_real_sdk_transport_sends_auth_on_handshake_and_tool_read(monkeypatch):
    spec={'url':'http://127.0.0.1:9/mcp','bearer_token_env':'FN_TEST_AUTH'}
    secret='synthetic-secret-for-test'
    monkeypatch.setenv('FN_TEST_AUTH',secret)
    httpx=host_stdio.httpx
    seen=[]
    def respond(request):
        assert request.headers['authorization']=='Bearer '+secret
        if request.method=='DELETE':return httpx.Response(200,json={})
        if request.method=='GET':return httpx.Response(405)
        body=json.loads(request.content);method=body['method'];seen.append(method)
        if 'id' not in body:return httpx.Response(202)
        rid=body['id']
        if method=='initialize':result={'protocolVersion':'2025-03-26','capabilities':{'tools':{}},'serverInfo':{'name':'auth-fixture','version':'0'}}
        elif method=='tools/list':result={'tools':[]}
        else:return httpx.Response(200,json={'jsonrpc':'2.0','id':rid,'error':{'code':-32601,'message':'not supported'}})
        return httpx.Response(200,json={'jsonrpc':'2.0','id':rid,'result':result})
    real=httpx.AsyncClient
    def create(**kwargs):
        assert kwargs['trust_env'] is False and kwargs['follow_redirects'] is False
        return real(transport=httpx.MockTransport(respond),**kwargs)
    monkeypatch.setattr(httpx,'AsyncClient',create)
    async def invoke():
        async with host_stdio._sdk_http_client(spec,2) as client:
            result=await client.list_tools()
            assert result.tools==[]
    anyio.run(invoke)
    assert 'initialize' in seen and 'tools/list' in seen


def test_existing_mcp_profile_ref_binds_exact_endpoint_without_copying_secret(tmp_path):
    path=tmp_path/'mcp.toml'
    path.write_text('[mcp_servers.fixture]\nurl="http://127.0.0.1:9/mcp"\n[mcp_servers.fixture.http_headers]\nAuthorization="Bearer synthetic-private-test"\n')
    path.chmod(0o600)
    spec={'url':'http://127.0.0.1:9/mcp','mcp_auth_ref':{'path':str(path),'server':'fixture'}}
    assert host_stdio._auth_headers(spec)=={'Authorization':'Bearer synthetic-private-test'}
    assert 'synthetic-private-test' not in json.dumps(spec)
    wrong=dict(spec,url='http://127.0.0.1:10/mcp')
    with pytest.raises(host_stdio.HostFacadeError,match='mismatched'):
        host_stdio._auth_headers(wrong)
    with pytest.raises(host_stdio.HostFacadeError):
        host_stdio._auth_headers(dict(spec,mcp_auth_ref={'path':str(tmp_path/'absent'),'server':'fixture'}))
