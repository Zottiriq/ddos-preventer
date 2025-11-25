# core/iptables_hardening.py
import subprocess
import logging
import config
from . import ipset_manager

logger = logging.getLogger("ddos-preventer")

IPTABLES_FILTER_CHAIN = "DDOS_FILTER"

def _run_shell(cmd):
    """iptables veya sysctl komutlarını çalıştırır ve hataları yakalar."""
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
            logger.error(f"{param} geçici olarak ayarlanamadı.")
            return

        conf_path = "/etc/sysctl.conf"
        setting_line = f"{param} = {value}\n"

        with open(conf_path, 'a+') as f:
            f.seek(0)
            content = f.read()
            if setting_line.strip().split('=')[0].strip() in content:
                logger.info(f"{param} ayarı zaten mevcut.")
            else:
                f.write(f"\n# {comment}\n{setting_line}")
                logger.info(f"{param} ayarı kalıcı olarak eklendi.")

    except Exception as e:
        logger.error(f"{param} ayarlanırken bir hata oluştu: {e}")

def enable_syn_cookies():
    """SYN Cookie korumasını etkinleştirir"""
    try:
        _set_sysctl_param(
            "net.ipv4.tcp_syncookies",
            "1",
            "Enabled by DDoS-Preventer for SYN Flood protection"
        )
        logger.info("SYN Cookie koruması aktif edildi.")
    except Exception as e:
        logger.error(f"SYN Cookie ayarlanırken hata oluştu: {e}")

def adjust_conntrack_settings():
    """Conntrack tablosu boyutunu doğrudan ayarlar."""
    param = "net.netfilter.nf_conntrack_max"
    target_value = config.KERNEL_CONNTRACK_MAX

    try:
        _set_sysctl_param(
            param,
            target_value,
            "Increased by DDoS-Preventer to handle more connections"
        )
        logger.info(f"{param} {target_value} olarak ayarlandı.")
    except Exception as e:
        logger.error(f"{param} ayarlanırken hata oluştu: {e}")


def setup_kernel_level_protection():
    """
    SYN Flood ve diğer temel ağ saldırılarına karşı iptables kurallarını ayarlar.
    """
    logger.info("Kernel seviyesi iptables koruma kuralları ayarlanıyor...")
    _run_shell(["iptables", "-N", IPTABLES_FILTER_CHAIN])
    _run_shell(["iptables", "-I", "INPUT", "1", "-j", IPTABLES_FILTER_CHAIN])

    # --- YENİ ve GÜÇLENDİRİLMİŞ KURAL SETİ ---
    
    # 1. ipset listesindeki IP'leri en başta engelle
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN,
                "-m", "set", "--match-set", config.DEFAULT_IPSET_NAME, "src",
                "-j", "DROP"])

    # 2. Kurulmuş ve ilgili bağlantılardan gelen paketlere her zaman izin ver. Bu, performansı artırır.
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, 
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", 
                "-j", "ACCEPT"])

    # 3. Geçersiz paketleri düşür
    _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, 
                "-m", "conntrack", "--ctstate", "INVALID", 
                "-j", "DROP"])

    # 4. Genel UDP hız limitini uygula
    if config.ENABLE_UDP_PROTECTION:
        logger.info(f"UDP per-IP hız limiti etkin ({config.UDP_LIMIT_RATE})...")

        _run_shell([
            "iptables", "-A", IPTABLES_FILTER_CHAIN,
            "-p", "udp",
            "-m", "hashlimit",
            "--hashlimit", config.UDP_LIMIT_RATE,
            "--hashlimit-burst", config.UDP_LIMIT_BURST,
            "--hashlimit-mode", "srcip",
            "--hashlimit-name", "udp_rate",
            "-j", "ACCEPT"
        ])

        _run_shell([
            "iptables", "-A", IPTABLES_FILTER_CHAIN,
            "-p", "udp",
            "-j", "DROP"
        ])
    if config.ENABLE_SYN_FLOOD_PROTECTION:
        # 5. SYN Flood'a karşı AKILLI KORUMA (hashlimit ile)
        _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN,
                    "-p", "tcp", "--syn",
                    "-m", "hashlimit",
                    "--hashlimit-upto", config.IPTABLES_SYN_LIMIT_RATE,
                    "--hashlimit-burst", config.IPTABLES_SYN_LIMIT_BURST,
                    "--hashlimit-mode", "srcip",
                    "--hashlimit-name", "conn_rate",
                    "-j", "ACCEPT"])
                    
        # 6. Geri kalan her şeyi (hız limitini aşan SYN'ler, istenmeyen diğer paketler) düşür.
        _run_shell(["iptables", "-A", IPTABLES_FILTER_CHAIN, "-j", "DROP"])

        logger.info("Gelişmiş Kernel seviyesi iptables koruması aktif.")

def verify_iptables_rules():
    """DDOS_FILTER ve INPUT bağlantısı yerinde mi kontrol eder."""
    # Zincir var mı?
    chain_ok = _run_shell(["iptables", "-L", IPTABLES_FILTER_CHAIN])
    if chain_ok is None:
        logger.error("DDOS_FILTER zinciri kayıp!")
        return False

    # INPUT → DDOS_FILTER var mı?
    input_ok = _run_shell(["iptables", "-C", "INPUT", "-j", IPTABLES_FILTER_CHAIN])
    if input_ok is None:
        logger.error("INPUT zinciri DDOS_FILTER’e bağlanmamış!")
        return False

    return True

def cleanup_kernel_level_protection():
    """Eklenen tüm kernel seviyesi iptables koruma kurallarını temizler."""
    logger.info("Kernel seviyesi iptables koruma kuralları temizleniyor...")
    _run_shell(["iptables", "-D", "INPUT", "-j", IPTABLES_FILTER_CHAIN])
    _run_shell(["iptables", "-F", IPTABLES_FILTER_CHAIN])
    _run_shell(["iptables", "-X", IPTABLES_FILTER_CHAIN])
    logger.info("Kernel seviyesi iptables koruması temizlendi.")
