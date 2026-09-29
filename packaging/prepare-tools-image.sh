#!/bin/bash
# Run only inside a newly imported Ubuntu Base build distribution.
set -euo pipefail
deps="$1"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends nmap sqlmap nikto whatweb gobuster ffuf curl jq ca-certificates unzip wget python3 python3-requests git dirb
apt-get install -y --no-install-recommends libio-socket-ssl-perl
# Ubuntu's Nikto 2.1.5 fails with its bundled LibWhisker; use the official 2.5.0 source.
mkdir -p /opt/nikto
tar -xzf "$deps/nikto.tar.gz" --strip-components=1 -C /opt/nikto
printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto
chmod 755 /usr/local/bin/nikto
nikto -Version
unzip -p "$deps/nuclei.zip" nuclei > /usr/local/bin/nuclei
chmod 755 /usr/local/bin/nuclei
mkdir -p /root/nuclei-templates /usr/share/wordlists /usr/share/doc/hexhound
tar -xzf "$deps/nuclei-templates.tar.gz" --strip-components=1 -C /root/nuclei-templates
ln -sf /usr/share/dirb/wordlists/common.txt /usr/share/wordlists/hexhound-common.txt
printf '[user]\ndefault=root\n[network]\nhostname=hexhound-tools\n' > /etc/wsl.conf
for tool in nmap sqlmap nikto whatweb gobuster ffuf nuclei curl python3; do command -v "$tool"; done
nuclei -version
test -s /usr/share/wordlists/hexhound-common.txt
test -d /root/nuclei-templates/http
dpkg-query -W > /usr/share/doc/hexhound/packages.txt
# No user distribution is exported; clean transient state from this build image.
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cache /root/.bash_history
find /var/log -type f -exec truncate -s 0 {} \;
truncate -s 0 /etc/machine-id
printf '127.0.0.1 localhost\n::1 localhost\n' > /etc/hosts
