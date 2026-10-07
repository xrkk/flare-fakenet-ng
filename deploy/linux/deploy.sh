#!/bin/bash
set -eu
D=/tmp/lnxfn-deploy
sudo mkdir -p /opt/fakenet-ng /etc/fakenet-ng-linux
sudo python3 -m venv /opt/fakenet-ng/venv
/opt/fakenet-ng/venv/bin/pip install --no-index --find-links $D/wheels \
    --prefer-binary mcp==2.1.1 uvicorn==0.52.4 starlette==1.6.0 \
    pydantic==2.13.5 dpkt==1.9.8 dnslib==0.9.26
/opt/fakenet-ng/venv/bin/pip install --no-index cython setuptools
# PyPI NetfilterQueue 1.1.0 sdist breaks under py3.12 (curexc_type);
# build the frozen upstream master snapshot instead (see README.md).
sudo tar xzf $D/netfilterqueue-upstream-master.tar.gz -C /tmp/
/opt/fakenet-ng/venv/bin/pip install --no-index --no-build-isolation /tmp/python-netfilterqueue-master/
sudo tar xzf $D/fakenet-src.tar.gz -C /opt/fakenet-ng/
sudo install -m 0755 $D/lnxfn-serve.py /opt/fakenet-ng/lnxfn-serve.py
if [ ! -f /etc/fakenet-ng-linux/token ]; then
  sudo python3 - "$@" <<'PY'
import secrets, os
os.makedirs('/etc/fakenet-ng-linux', exist_ok=True)
fd = os.open('/etc/fakenet-ng-linux/token', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
os.write(fd, secrets.token_hex(32).encode()); os.close(fd)
PY
fi
sudo install -m 0644 $D/fakenet-ng-linux.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fakenet-ng-linux.service
sleep 2
systemctl is-active fakenet-ng-linux.service
