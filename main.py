import re
import socket
from collections import Counter


def scan_ports(host: str, ports: list[int], timeout: float = 0.4) -> list[int]:
    """Проверяет, какие TCP-порты открыты на указанном хосте."""
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
    return open_ports


def detect_bruteforce(log_lines: list[str], limit: int = 3) -> dict[str, int]:
    """Ищет IP-адреса с частыми неудачными попытками входа по SSH."""
    pattern = re.compile(r"Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)")
    attempts: Counter[str] = Counter()
    for line in log_lines:
        match = pattern.search(line)
        if match:
            attempts[match.group(1)] += 1
    return {ip: count for ip, count in attempts.items() if count >= limit}


def generate_ufw_rules(allowed_ports: list[int]) -> list[str]:
    """Формирует базовые правила защиты для файрвола UFW в Linux."""
    rules = [
        "sudo ufw default deny incoming",
        "sudo ufw default allow outgoing",
    ]
    for port in allowed_ports:
        rules.append(f"sudo ufw allow {port}/tcp")
    rules.append("sudo ufw enable")
    return rules


def generate_sysctl_hardening() -> list[str]:
    """Формирует параметры ядра Linux для защиты от сетевых атак."""
    return [
        "net.ipv4.tcp_syncookies = 1",
        "net.ipv4.conf.all.rp_filter = 1",
        "net.ipv4.conf.all.accept_redirects = 0",
        "net.ipv4.icmp_echo_ignore_broadcasts = 1",
    ]


if __name__ == "__main__":
    # 1. Проверка открытых портов на локальной машине
    target_host = "127.0.0.1"
    ports_to_check = [22, 80, 443, 3306, 5432, 8000, 8080]
    opened = scan_ports(target_host, ports_to_check)
    print(f"[1] Открытые порты на {target_host}: {opened}")

    # 2. Анализ логов на подбор паролей (brute-force)
    sample_logs = [
        "Failed password for root from 185.220.101.4 port 51201 ssh2",
        "Failed password for root from 185.220.101.4 port 51202 ssh2",
        "Failed password for admin from 185.220.101.4 port 51203 ssh2",
        "Failed password for ubuntu from 10.0.0.15 port 49110 ssh2",
    ]
    suspicious_ips = detect_bruteforce(sample_logs, limit=3)
    print(f"[2] Подозрительные IP (атаки перебора): {suspicious_ips}")

    # 3. Правила файрвола UFW
    print("\n[3] Рекомендуемые правила UFW для Linux:")
    for rule in generate_ufw_rules([22, 80, 443]):
        print("  ", rule)

    # 4. Защита сетевого стека через sysctl
    print("\n[4] Параметры защиты ядра Linux (sysctl):")
    for param in generate_sysctl_hardening():
        print("  ", param)