# 🛡️ DDoS-Preventer
Lightweight, kernel-assisted DDoS protection built with Python + iptables + ipset.  
All incoming traffic is inspected before it reaches any backend service, while malicious packets are dropped directly inside the Linux kernel.

Language: Python  
Firewall: iptables/ipset  
Systemd: Supported  
IPv4: Supported  
IPv6: Not Supported

------------------------------------------------------------

## 📌 Features
- Kernel-level filtering (SYN flood, UDP flood, malformed packets)
- Layer 3 IP blocking using ipset
- Layer 4 token-bucket rate limiting
- Per-IP concurrent connection limiting
- Whitelist + automatic blocklist
- NAT PREROUTING → Python proxy redirection
- systemd service integration
- Protects all IPv4 ports (HTTP, SSH, DB, game servers, etc.)

------------------------------------------------------------

# 🔥 System Overview

### Kernel
Immediately blocks low-level attacks such as SYN floods, UDP floods, and malformed packets.

### iptables NAT
Redirects all incoming HTTP/TCP traffic to the Python security layer before it touches the real service.

### Python Proxy
Applies rate limiting, connection limiting, whitelist and blacklist validation.

### Result
Clean traffic → forwarded to the backend  
Malicious traffic → dropped at kernel level  

------------------------------------------------------------

# 🔎 Detailed Traffic Flow Explanation

1) Packet arrives at the server  
2) Linux kernel inspects it through iptables  
3) SYN/UDP flood and malformed packet checks occur  
4) NAT PREROUTING redirects the packet to the Python proxy  
5) Python determines the original target port  
6) Rate-limit, connection-limit, whitelist and blacklist checks are applied  
7) Clean packets are forwarded to the real service (Nginx/SSH/DB/Game servers)

------------------------------------------------------------

# 🔎 Traffic Flow Diagram

    Incoming Packet
          ↓
    [ Linux Kernel ]
      - Blocklist check
      - SYN/UDP flood detection
      - Malformed packet detection
          ↓
    [ NAT PREROUTING ]
          ↓
    [ Python Proxy ]
      - Rate limit
      - Connection limit
      - Whitelist / Blacklist
          ↓
    [ Real Service ]
      - Nginx / SSH / DB / Game servers

------------------------------------------------------------

# 🚦 How Incoming Traffic Is Processed (Summary)

    Packet arrives
    Kernel checks (blocklist, SYN/UDP flood, malformed packet)
    NAT redirects traffic to Python
    Python identifies original destination port
    Python applies rate + connection limits
    Clean traffic is forwarded to the real service

------------------------------------------------------------

# 📁 Project Structure

    /opt/deneme2/main.py
    /opt/deneme2/cleanup_rules.sh
    /etc/ddos_preventer/
    /home/log/ddos-preventer.log

------------------------------------------------------------

# 🧩 Installation

    git clone https://github.com/keremincii/ddos-preventer
    cd ddos-preventer
    sudo ./install.sh

------------------------------------------------------------

# 🖥 systemd Usage

    sudo systemctl start ddos-preventer
    sudo systemctl stop ddos-preventer
    sudo systemctl restart ddos-preventer
    sudo journalctl -u ddos-preventer -f

------------------------------------------------------------

# 📜 Whitelist / Blocklist Management

    # Whitelist
    sudo ipset list ddos_whitelist

    # Blocklist
    sudo ipset list ddos_blocklist

------------------------------------------------------------

# ⚠ Limitations
- IPv6 is not supported  
- Only IPv4 traffic is filtered  
- iptables/ipset rules must not be overridden by other firewall tools  

------------------------------------------------------------

# 🤝 Contributing
Pull requests and issue reports are welcome.

------------------------------------------------------------

# 📄 License
MIT License.
