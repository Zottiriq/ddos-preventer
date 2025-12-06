DDoS Preventer for LAN

A lightweight iptables + ipset + asyncio-based transparent DDoS mitigation proxy for Linux servers.
Protects LAN/WAN environments with minimal overhead and automatic TCP port discovery.

Getting Started

This guide explains how to install, configure, and run DDoS Preventer.

Prerequisites

Linux with iptables/ipset and Python 3.9+

System packages

sudo apt install iptables ipset iproute2 procps -y


Python dependencies

pip install -r requirements.txt

Installation

Follow these steps to set up the project.

1. Clone the repository
git clone https://github.com/yourusername/ddos-preventer.git
cd ddos-preventer

2. Configure defaults (config.py)

Default limits:

DEFAULT_RATE = 20
DEFAULT_BURST = 50
DEFAULT_CONN_LIMIT = 100
DEFAULT_BLOCK_SEC = 30


Per-port overrides:

TARGET_PORTS = {
    22:  {'protocol': 'tcp',  'rate': 5,  'burst': 10,  'conn_limit': 10},
    80:  {'protocol': 'http', 'rate': 15, 'burst': 25},
    443: {'protocol': 'tcp',  'rate': 100, 'burst': 200}
}

3. Optional: Edit whitelist
/etc/ddos_preventer/whitelist.txt


Example:

192.168.1.10
10.0.0.0/24
2001:db8::/32

4. Run manually
sudo python3 main.py


Starts:

HTTP proxy → 0.0.0.0:8081

TCP proxy → 0.0.0.0:9000

Stop:

Ctrl + C

Systemd Setup
Install service
sudo cp ddos-preventer.service /etc/systemd/system/
sudo systemctl daemon-reload

Enable & start
sudo systemctl enable ddos-preventer
sudo systemctl start ddos-preventer


Stop:

sudo systemctl stop ddos-preventer

Logging

Default log path:

/home/log/ddos-preventer.log

Architecture Overview
main.py                     → startup, proxies, iptables/ipset apply/cleanup
config.py                   → limits, overrides, log paths
core/ipset_manager.py       → blocklist / whitelist
core/iptables_manager.py    → NAT redirection
core/iptables_hardening.py  → DDOS_FILTER chain & sysctl hardening
core/mitigation_manager.py  → token-bucket + conn counting
handlers/http_handler.py    → HTTP reverse proxy
handlers/generic_tcp_handler.py → Transparent TCP proxy

Contributing

Pull requests and issues are welcome.

License

Add your preferred license (MIT, Apache 2.0, GPL).
