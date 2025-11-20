# core/iptables_manager.py
import subprocess
import logging
import config

logger = logging.getLogger("ddos-preventer")

def _run_shell(cmd):
    try:
        subprocess.run(cmd, check=True, text=True, timeout=5, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        if "does not exist" in e.stderr or "already exists" in e.stderr:
            return True 
        logger.error("iptables komut hatası '%s': %s", " ".join(cmd), e.stderr.strip())
        return False

def setup_transparent_proxy_rules():
    logger.info("Transparent Proxy için iptables yönlendirme kuralları ayarlanıyor...")

    _run_shell(["iptables", "-t", "nat", "-N", config.IPTABLES_CHAIN])

    # <--- EKLENDİ: Fortinet (500, 4500, 10443) Proxy harici tutulacak --->
    EXCLUDED_FROM_PROXY = {
        21,    # FTP
        22,    # SSH
        500,   # IPsec IKE (Fortinet)
        4500,  # IPsec NAT-T (Fortinet)
        1194,  # OpenVPN
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        10443, # Fortinet SSL VPN (Alternatif Port)
        51820  # WireGuard
    }

    for port, settings in config.TARGET_PORTS.items():
        if port in EXCLUDED_FROM_PROXY:
            logger.info(f"Port {port} Kernel (iptables) yönetimine bırakıldı. Proxy'den geçmeyecek.")
            continue

        proto_type = settings.get('protocol', 'tcp')
        redirect_port = config.HTTP_PROXY_LISTEN_PORT if proto_type == 'http' else config.GENERIC_TCP_LISTEN_PORT

        _run_shell([
            "iptables", "-t", "nat", "-A", config.IPTABLES_CHAIN,
            "-p", "tcp", "--dport", str(port),
            "-j", "REDIRECT", "--to-port", str(redirect_port)
        ])

    _run_shell(["iptables", "-t", "nat", "-A", "PREROUTING", "-j", config.IPTABLES_CHAIN])
    logger.info("iptables yönlendirme kuralları aktif.")

def cleanup_transparent_proxy_rules():
    logger.info("iptables yönlendirme kuralları temizleniyor...")
    _run_shell(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", config.IPTABLES_CHAIN])
    _run_shell(["iptables", "-t", "nat", "-F", config.IPTABLES_CHAIN])
    _run_shell(["iptables", "-t", "nat", "-X", config.IPTABLES_CHAIN])
    logger.info("iptables temizlendi.")