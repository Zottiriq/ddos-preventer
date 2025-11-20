# config.py

# --- KERNEL & IPTABLES AYARLARI ---
DEFAULT_IPSET_NAME = "ddos_blocklist"
IPTABLES_CHAIN = "DDOS_GATEWAY"

IPTABLES_SYN_LIMIT_RATE = "10/s"
IPTABLES_SYN_LIMIT_BURST = 20

ENABLE_UDP_PROTECTION = True
UDP_LIMIT_RATE = "100/s"
UDP_LIMIT_BURST = 200

KERNEL_CONNTRACK_MAX = 131072

# --- UYGULAMA KATMANI LİMİTLERİ ---
DEFAULT_RATE = 20
DEFAULT_BURST = 50
DEFAULT_CONN_LIMIT = 100
DEFAULT_BLOCK_SEC = 30

# --- KORUNACAK PORTLAR VE ÖZEL LİMİTLER ---
TARGET_PORTS = {
    # --- KERNEL (IPTABLES) TARAFINDAN YÖNETİLENLER ---
    21:    {'protocol': 'tcp', 'status': 'KERNEL_MANAGED', 'desc': 'FTP'},
    22:    {'protocol': 'tcp', 'status': 'KERNEL_MANAGED', 'desc': 'SSH'},
    500:   {'protocol': 'udp', 'status': 'KERNEL_MANAGED', 'desc': 'Fortinet IPsec IKE'},
    4500:  {'protocol': 'udp', 'status': 'KERNEL_MANAGED', 'desc': 'Fortinet IPsec NAT-T'},
    1194:  {'protocol': 'udp', 'status': 'KERNEL_MANAGED', 'desc': 'OpenVPN'},
    3306:  {'protocol': 'tcp', 'status': 'KERNEL_MANAGED', 'desc': 'MySQL'},
    5432:  {'protocol': 'tcp', 'status': 'KERNEL_MANAGED', 'desc': 'PostgreSQL'},
    6379:  {'protocol': 'tcp', 'status': 'KERNEL_MANAGED', 'desc': 'Redis'},
    10443: {'protocol': 'tcp', 'status': 'KERNEL_MANAGED', 'desc': 'Fortinet SSL VPN'},
    51820: {'protocol': 'udp', 'status': 'KERNEL_MANAGED', 'desc': 'WireGuard'},

    # --- PYTHON PROXY TARAFINDAN YÖNETİLENLER ---
    80: {
        'protocol': 'http',
        'rate': 15,
        'burst': 25
    },
    443: {
        'protocol': 'tcp',
        'rate': 100,
        'burst': 200
    }
}

WELL_KNOWN_HTTP_PORTS = {80, 5000, 8000, 8080}

HTTP_PROXY_LISTEN_PORT = 8081
GENERIC_TCP_LISTEN_PORT = 9000

DEFAULT_LOG_FILE = "/home/log/ddos-preventer.log"