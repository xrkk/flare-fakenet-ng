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
