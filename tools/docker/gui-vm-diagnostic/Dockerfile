FROM vpb/ubuntu-base:24.04-local

ARG DEBIAN_FRONTEND=noninteractive
ARG PYTHON_VERSION=3.11.9
ARG PYTHON_INSTALLER_SHA256=5ee42c4eee1e6b4464bb23722f90b45303f79442df63083f05322f1785f5fdde

ENV WINEARCH=win64 \
    WINEPREFIX=/opt/fakenet-wine \
    WINEDEBUG=-all \
    WINEDLLOVERRIDES=mscoree,mshtml= \
    DISPLAY=:99

RUN dpkg --add-architecture i386 \
    && sed -i 's/ noble main$/ noble main universe/' /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl git python3 tini unzip wine wine32:i386 wine64 xvfb \
    && rm -rf /var/lib/apt/lists/*

COPY python-${PYTHON_VERSION}-amd64.exe /tmp/python-amd64.exe

RUN echo "${PYTHON_INSTALLER_SHA256}  /tmp/python-amd64.exe" | sha256sum -c - \
    && mkdir -p "${WINEPREFIX}" \
    && xvfb-run -a wineboot --init \
    && xvfb-run -a wine /tmp/python-amd64.exe /quiet \
        InstallAllUsers=1 TargetDir=C:\\Python311 \
        Include_launcher=0 Include_test=0 PrependPath=0 \
    && test -f "${WINEPREFIX}/drive_c/Python311/python.exe" \
    && rm -f /tmp/python-amd64.exe

RUN xvfb-run -a wine C:\\Python311\\python.exe -m pip install \
        --disable-pip-version-check --no-cache-dir \
        certifi cryptography dnslib dpkt jinja2 netifaces-plus==0.12.5 pyftpdlib \
        pyopenssl pydivert==2.0.9 pyinstaller==6.22.0 pytest==8.3.5 \
    && xvfb-run -a wine C:\\Python311\\python.exe -c \
        "import certifi, cryptography, dnslib, dpkt, jinja2, netifaces, OpenSSL, pydivert, PyInstaller, pytest; assert callable(netifaces.interfaces); assert callable(netifaces.ifaddresses)" \
    && xvfb-run -a wine C:\\Python311\\python.exe -m PyInstaller --version \
    && xvfb-run -a wine C:\\Python311\\python.exe -m pytest --version \
    && chmod -R a+rwX "${WINEPREFIX}"

ARG HOST_UID=1000
ARG HOST_GID=1000
RUN chown -R "${HOST_UID}:${HOST_GID}" "${WINEPREFIX}"

WORKDIR /workspace

# Keep xvfb-run out of PID 1 so Xvfb's SIGUSR1 readiness notification is
# delivered to its shell trap when the image is used by ACC-002/ACC-006.
ENTRYPOINT ["/usr/bin/tini", "--"]
