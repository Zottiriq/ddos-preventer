## DDoS Preventer for LAN

This project is a lightweight iptables + ipset + asyncio-based transparent proxy that protects Linux servers against DDoS attacks on LAN/WAN networks.

### Features
- Transparent proxying of inbound TCP traffic via iptables NAT
- `aiohttp` HTTP reverse proxy plus a generic TCP proxy
- Per-IP rate limiting, burst limiting, and concurrent connection limiting
- Dynamic ipset blocklist/whitelist management
- Kernel hardening: SYN cookies, conntrack tuning, UDP/SYN flood protection
- Automatic listening port discovery using `ss -lnt`

### Requirements
- Linux with iptables, ipset, iproute2, procps
- Python 3.9+ and root privileges
- Python dependency: `aiohttp` (install via `pip install -r requirements.txt`)

### Configuration
Edit `config.py` to adjust:
- `TARGET_PORTS` for per-port limits (rate, burst, conn_limit, protocol)
- `WELL_KNOWN_HTTP_PORTS` for auto HTTP classification
- `DEFAULT_*` values for global rate/burst/connection limits
- Kernel tuning flags (UDP protection, SYN flood protection, conntrack size)
- Proxy listen ports and log file location

### Running
```bash
sudo python3 main.py
```
Startup flow:
1. Applies sysctl settings (SYN cookies, conntrack max)
2. Prepares ipset blocklist/whitelist
3. Installs iptables NAT and filter chains
4. Discovers open TCP ports and protects them
5. Starts HTTP proxy on `0.0.0.0:8081` and generic TCP proxy on `0.0.0.0:9000`

Press `Ctrl+C` to stop; iptables and ipset changes are cleaned automatically.

### Systemd Service
Deploy the provided unit file:
```bash
sudo cp ddos-preventer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ddos-preventer
sudo systemctl start ddos-preventer
```

### Whitelist
Trusted IPs/CIDRs go into `/etc/ddos_preventer/whitelist.txt`. Each entry is loaded into the `ddos_whitelist` ipset set and bypasses rate/connection limits.

### Logging
Default log path: `/home/log/ddos-preventer.log` (changeable via `config.py`).

### Security Notes
- Must run as root; test in staging before production
- Review existing iptables rules to avoid conflicts
- Tune UDP/SYN thresholds for high-traffic environments

### Contributing
Open issues or PRs for bugs or enhancements. Follow the existing logging/style conventions.

### License
Add your preferred license file (e.g., MIT, Apache 2.0, GPL) and reference it here.
