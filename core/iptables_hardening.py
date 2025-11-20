# core/iptables_hardening.py
import subprocess
import logging
import config
from . import ipset_manager

logger = logging.getLogger("ddos-preventer")

IPTABLES_FILTER_CHAIN = "DDOS_FILTER"

def _run_shell(cmd):
    try:
        result = subprocess.run(cmd, check=True, text=True, timeout=5, capture_output=True)
        return result
    except subprocess.CalledProcessError as e:
        if "does not exist" in e.stderr or "already exists" in e.stderr:
            return None
        logger.error("Shell komut hatası '%s': %s", " ".join(cmd), e.stderr.strip())
        return None
    except Exception as e:
        logger.error("Shell komutu çalıştırılamadı '%s': %s", " ".join(cmd), e)
        return None

def _set_sysctl_param(param, value, comment="DDoS-Preventer"):
    try:
        logger.info(f"Kernel parametresi ayarlanıyor: {param} = {value}")
        if not _run_shell(["sysctl", "-w", f"{param}={value}"]):
            return
        conf_path = "/etc/sysctl.conf"
        setting_line = f"{param} = {value}\n"
        with open(conf_path, 'r+') as f:
            if setting_line.strip().split('=')[0].strip() not in f.read():
                f.seek(0, 2)
                f.write(f"\n# {comment}\n{setting_line}")
    except Exception as e:
        logger.error(f"{param} ayarlanırken hata: {e}")

def enable_syn_cookies():
    result = _run_shell(["sysctl", "net.ipv4.tcp_syncookies"])
    if not (result and "= 1" in result.stdout):
        _set_sysctl_param("net.ipv4.tcp_syncookies", "1")

def adjust_conntrack_settings():
    param = "net.netfilter.nf_conntrack_max"
    _set_sysctl_param(param, str(config.KERNEL_CONNTRACK_MAX))

def setup_kernel_level_protection():
    logger.info("Kernel seviyesi iptables koruma kuralları ayarlanıyor...")
    _run_shell(["iptables", "-N", IPTABLES_FILTER_CHAIN])
    _run_shell(["iptables", "-I", "INPUT", "1", "-j", IPTABLES_FILTER_CHAIN])

    # 1. IPSET (Blacklist) kontrolü
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN,
                "-m", "set", "--match-set", config.DEFAULT_IPSET_NAME, "src", "-j", "DROP"])

    # 2. ESTABLISHED bağlantılara izin ver
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, 
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

    # 3. Geçersiz paketleri düşür
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, 
                "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"])

    # --- KERNEL YÖNETİMLİ SERVİSLER ---
    
    # A) SSH Brute-Force Koruması
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "tcp", "--dport", "22", 
                "-m", "state", "--state", "NEW", "-m", "recent", "--set", "--name", "SSH_LIMIT", "--rsource"])
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "tcp", "--dport", "22", 
                "-m", "state", "--state", "NEW", "-m", "recent", "--update", "--seconds", "60", "--hitcount", "7", 
                "--name", "SSH_LIMIT", "--rsource", "-j", "DROP"])
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "tcp", "--dport", "22", "-j", "ACCEPT"])

    # B) Veritabanı Koruması
    db_ports = "3306,5432,6379"
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "tcp", "-m", "multiport", "--dports", db_ports,
                "-m", "hashlimit", "--hashlimit-upto", "50/s", "--hashlimit-burst", "100",
                "--hashlimit-mode", "srcip", "--hashlimit-name", "db_rate", "-j", "ACCEPT"])

    # C) VPN (Fortinet, OpenVPN, WireGuard) - ÖZEL İZİN
    # Fortinet IPsec (500, 4500) ve diğer UDP VPN portları
    vpn_udp_ports = "500,4500,1194,51820"
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "udp", "-m", "multiport", "--dports", vpn_udp_ports, "-j", "ACCEPT"])

    # Fortinet SSL VPN (Genellikle 10443 kullanılır, 443 ise web ile çakışabilir)
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "tcp", "--dport", "10443", "-j", "ACCEPT"])

    # 4. Genel UDP Limiti
    if config.ENABLE_UDP_PROTECTION:
        _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "udp", 
                    "-m", "limit", "--limit", config.UDP_LIMIT_RATE, "--limit-burst", str(config.UDP_LIMIT_BURST),
                    "-j", "ACCEPT"])
        _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "udp", "-j", "DROP"])

    # 5. Genel SYN Flood Koruması
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-p", "tcp", "--syn",
                "-m", "hashlimit", "--hashlimit-upto", "25/s", "--hashlimit-burst", "50",
                "--hashlimit-mode", "srcip", "--hashlimit-name", "conn_rate", "-j", "ACCEPT"])
                
    # 6. Kalan her şeyi düşür
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-j", "DROP"])

    logger.info("Gelişmiş Kernel seviyesi iptables koruması aktif.")

def cleanup_kernel_level_protection():
    logger.info("Kernel seviyesi iptables temizleniyor...")
    _run_shell(["iptables", "-D", "INPUT", "-j", IPTABLES_FILTER_CHAIN])
    _run_shell(["iptables", "-F", IPTABLES_FILTER_CHAIN])
    _run_shell(["iptables", "-X", IPTABLES_FILTER_CHAIN])