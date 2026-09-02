# Windows domain-takeover wheel sources

Target environment: CPython 3.13.7, Windows x64. All VM installations use
`--no-index --require-hashes` and only the wheels in this directory.

| Distribution | Version | Wheel | SHA-256 | Source |
|---|---:|---|---|---|
| cffi | 2.1.1 | `cffi-2.1.1-cp313-cp313-win_amd64.whl` | `1aa5645c30469b09530c4ebca77ebf8f17618293c58f8549cb1a543a50236e7d` | PyPI official release |
| cryptography | 50.0.0 | `cryptography-50.0.0-cp311-abi3-win_amd64.whl` | `bd1c592e4d5974f0d08d4888e432157adba757c66da0246918e43677fafa2d30` | PyPI official release |
| dnslib | 0.9.26 | `dnslib-0.9.26-py3-none-any.whl` | `e68719e633d761747c7e91bd241019ef5a2b61a63f56025939e144c841a70e0d` | PyPI official release |
| dpkt | 1.9.8 | `dpkt-1.9.8-py3-none-any.whl` | `4da4d111d7bf67575b571f5c678c71bddd2d8a01a3d57d489faf0a92c748fbfd` | PyPI official release |
| Jinja2 | 3.1.6 | `jinja2-3.1.6-py3-none-any.whl` | `85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67` | PyPI official release |
| MarkupSafe | 3.0.3 | `markupsafe-3.0.3-cp313-cp313-win_amd64.whl` | `9a1abfdc021a164803f4d485104931fb8f8c1efd55bc6b748d2f5774e78b62c5` | PyPI official release |
| netifaces-plus | 0.12.5 | `netifaces_plus-0.12.5-cp313-cp313-win_amd64.whl` | `ee3287ddbf73221cd4310a7a087f22e4c8c134c4d22bec9d4a65aa75f970eb8f` | PyPI official release |
| pyasynchat | 1.0.5 | `pyasynchat-1.0.5-py3-none-any.whl` | `35b7859515693e479e8d95ebe9f32cbf4d6312ab7599ced39fc24699e51de46f` | PyPI official release; required by pyftpdlib on Python 3.12+ |
| pyasyncore | 1.0.5 | `pyasyncore-1.0.5-py3-none-any.whl` | `269bbc5252671827387636822841a1fb721ec6e858b23a3e12cf92eb1f97da2a` | PyPI official release; required by pyftpdlib/pyasynchat on Python 3.12+ |
| pycparser | 3.0 | `pycparser-3.0-py3-none-any.whl` | `b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992` | PyPI official release |
| PyDivert | 2.1.0 | `pydivert-2.1.0-py2.py3-none-any.whl` | `382db488e3c37c03ec9ec94e061a0b24334d78dbaeebb7d4e4d32ce4355d9da1` | PyPI official release |
| pyftpdlib | 2.2.0 | `pyftpdlib-2.2.0-py3-none-any.whl` | `1b6cc483ea645a7b813a734a53e734d3f9594f41f5431bb0d8c941c0ec6dddf8` | Locally built pure-Python wheel from the official PyPI sdist |
| pyOpenSSL | 26.4.0 | `pyopenssl-26.4.0-py3-none-any.whl` | `f0eb0cb2d581d3ad2b9c489468485e7f2ab6727d08401bcf9d824c3caddf3c1c` | PyPI official release |
| typing-extensions | 4.16.0 | `typing_extensions-4.16.0-py3-none-any.whl` | `481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8` | PyPI official release |

Official PyPI project pages use the form
`https://pypi.org/project/<distribution>/<version>/`.

`pyftpdlib` publishes no wheel in any PyPI release. Its wheel was built with
the host build toolchain from `pyftpdlib-2.2.0.tar.gz`, whose official PyPI
SHA-256 is
`4ba0642078792df63dd3b2e9c8f838f2a3ecf428c7518d5921c0530d53512acf`.
The source archive is intentionally not shipped to the VM. The generated
wheel remains subject to clean-VM CPython 3.13 compatibility acceptance.

## fakenetng-mcp service build wheels (added 2026-09-02, P01 IMP-P01-02)

These wheels serve a second, separate consumer: the pinned Docker/Wine
builder image (Windows CPython 3.11.9, PyInstaller 6.22.0) installs them
offline ("pip install --no-index --find-links wheelhouse mcp==2.1.1")
so the fakenetng-mcp service and its MCP SDK dependency can be frozen
into the onedir candidate package. They are not installed on the
acceptance VM; the frozen exe embeds its own runtime. Downloads were
resolved for cp311/win_amd64 on 2026-09-02 and are pinned by the SHA-256
values below. Dependency versions were resolved and verified together
against mcp==2.1.1 in a scratch venv before being recorded here.

| Distribution | Version | Wheel | SHA-256 | Source |
|---|---:|---|---|---|
| annotated-types | 0.8.0 | `annotated_types-0.8.0-py3-none-any.whl` | `f072f4d804ea359e4eaf198b1af7a8b0943881a87f31bb764f8bf219bb9419e0` | PyPI official release |
| anyio | 4.14.2 | `anyio-4.14.2-py3-none-any.whl` | `9f505dda5ac9f0c8309b5e8bd445a8c2bf7246f3ce950121e45ea15bc41d1494` | PyPI official release |
| attrs | 26.1.0 | `attrs-26.1.0-py3-none-any.whl` | `c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309` | PyPI official release |
| cffi | 2.1.1 | `cffi-2.1.1-cp311-cp311-win_amd64.whl` | `42f6930c31dc7f50732c9ae793c2786c7b6b044195967bbdde40bb9be81c4cc0` | PyPI official release |
| click | 8.5.0 | `click-8.5.0-py3-none-any.whl` | `255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360` | PyPI official release |
| cryptography | 50.0.1 | `cryptography-50.0.1-cp311-abi3-win_amd64.whl` | `aed8db4f6d71c51efb89530e12d9464e7bf2923d46c3205dc794a2a93f8c0648` | PyPI official release |
| h11 | 0.16.0 | `h11-0.16.0-py3-none-any.whl` | `63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86` | PyPI official release |
| httpcore2 | 2.12.0 | `httpcore2-2.12.0-py3-none-any.whl` | `7e04258ce01013d7d615e5b910a3b27fac937d7a95038227e79652b4ba3b4ceb` | PyPI official release |
| httpx2 | 2.12.0 | `httpx2-2.12.0-py3-none-any.whl` | `cc8b6eecb8661c146b8f89a60e97456ee086e91a784ed31ac450c3a9e613dd36` | PyPI official release |
| idna | 3.19 | `idna-3.19-py3-none-any.whl` | `815e7be7a7806d54abb586dc943addc79e8b2ee16915059658cbeff4b1b43bf4` | PyPI official release |
| jsonschema | 4.26.0 | `jsonschema-4.26.0-py3-none-any.whl` | `d489f15263b8d200f8387e64b4c3a75f06629559fb73deb8fdfb525f2dab50ce` | PyPI official release |
| jsonschema-specifications | 2025.9.1 | `jsonschema_specifications-2025.9.1-py3-none-any.whl` | `98802fee3a11ee76ecaca44429fda8a41bff98b00a0f2838151b113f210cc6fe` | PyPI official release |
| mcp | 2.1.1 | `mcp-2.1.1-py3-none-any.whl` | `1c6c31c5d6471c58db76af3af8af67f46d11d01f0a59077d0a308cbdb3d3e915` | PyPI official release |
| mcp-types | 2.1.1 | `mcp_types-2.1.1-py3-none-any.whl` | `26f9f7f03f2a5730717a5b98e2ab7eb640ac352d05a00cdc725c311864778295` | PyPI official release |
| opentelemetry-api | 1.44.0 | `opentelemetry_api-1.44.0-py3-none-any.whl` | `94b98c893a91b88657eaac1e3ba89618cdb85be6918196705354f34728b2cdef` | PyPI official release |
| pydantic | 2.13.5 | `pydantic-2.13.5-py3-none-any.whl` | `346a034f080da3755d8e9cb5e00e8b07de1d39e4f6e2c87d8ab7cafa0b269a73` | PyPI official release |
| pydantic-core | 2.46.5 | `pydantic_core-2.46.5-cp311-cp311-win_amd64.whl` | `40375c2d05acec10323e45dfe2077ac44bc74659008614af5069034e2cfc781c` | PyPI official release |
| pyjwt | 2.13.0 | `pyjwt-2.13.0-py3-none-any.whl` | `66adcc2aff09b3f1bbd95fc1e1577df8ac8723c978552fd43304c8a290ac5728` | PyPI official release |
| pywin32 | 312 | `pywin32-312-cp311-cp311-win_amd64.whl` | `d11417d84412f859b722fad0841b3614459ed0047f7542d8362e77884f6b6e8a` | PyPI official release (mcp==2.1.1 win32 marker dependency) |
| python-multipart | 0.0.32 | `python_multipart-0.0.32-py3-none-any.whl` | `ff6d3f776f16878c894e52e107296ffc890e913c611b1a4ec6c44e2821fe2e23` | PyPI official release |
| referencing | 0.37.0 | `referencing-0.37.0-py3-none-any.whl` | `381329a9f99628c9069361716891d34ad94af76e461dcb0335825aecc7692231` | PyPI official release |
| rpds-py | 2026.6.3 | `rpds_py-2026.6.3-cp311-cp311-win_amd64.whl` | `2c54a076ca4d370980ab57bc0e31df57bbe8d41340436a90ef8b1219a3cbb127` | PyPI official release |
| sse-starlette | 3.4.8 | `sse_starlette-3.4.8-py3-none-any.whl` | `6e82314c786709a3cd9520f2285cf9fff90e181e598e8a357b0cf80f66afba0d` | PyPI official release |
| starlette | 1.6.0 | `starlette-1.6.0-py3-none-any.whl` | `a86dd39d14bb45f85a3d18525215a9ef0cfd1f192ac793220e72598c90335f0c` | PyPI official release |
| truststore | 0.10.4 | `truststore-0.10.4-py3-none-any.whl` | `adaeaecf1cbb5f4de3b1959b42d41f6fab57b2b1666adb59e89cb0b53361d981` | PyPI official release |
| typing-inspection | 0.4.4 | `typing_inspection-0.4.4-py3-none-any.whl` | `65b8397ba37ccbce054456aaccddfc91e6e3083c92824df348d96ca832f3f147` | PyPI official release |
| uvicorn | 0.52.4 | `uvicorn-0.52.4-py3-none-any.whl` | `f86e41a149d7d05a9969337e3946a9c171c06a5d42680896daaba624aeac8da1` | PyPI official release |
