from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.request

# Couleurs ANSI (compatibles macOS, Linux et Windows 10/11)
if os.name == "nt":
    os.system("")

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

HOSTS_FILE = "hosts.json"
TRUSTED_FILE = "trusted_devices.json"
LOG_FILE = "monitor.log"

RISKY_PORTS = {
    21: "FTP (non chiffré)",
    23: "Telnet (non chiffré)",
    445: "SMB (cible ransomware)",
    3389: "RDP (accès bureau à distance)",
    8080: "HTTP alternatif",
}


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("NetBasicsPro")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(LOG_FILE, maxBytes=512 * 1024, backupCount=3, encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


logger = setup_logger()


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def print_banner() -> None:
    clear_screen()
    banner = f"""{YELLOW}{BOLD}********************************************************************
*                                                                  *
*       {CYAN}██████╗  ██████╗ ███╗   ██╗     ██╗ ██████╗ ██╗   ██╗██████╗ {YELLOW} *
*       {CYAN}██╔══██╗██╔═══██╗████╗  ██║     ██║██╔═══██╗██║   ██║██╔══██╗{YELLOW}*
*       {CYAN}██████╔╝██║   ██║██╔██╗ ██║     ██║██║   ██║██║   ██║██████╔╝{YELLOW}*
*       {CYAN}██╔══██╗██║   ██║██║╚██╗██║██   ██║██║   ██║██║   ██║██╔══██╗{YELLOW}*
*       {CYAN}██████╔╝╚██████╔╝██║ ╚████║╚█████╔╝╚██████╔╝╚██████╔╝██║  ██║{YELLOW}*
*       {CYAN}╚═════╝  ╚═════╝ ╚═╝  ╚═══╝ ╚════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝{YELLOW}*
*                                                                  *
*         {GREEN}NETBASICS PRO v2 | Scanner Réseau, Sécurité & Wi-Fi{YELLOW}      *
*       {RESET}Usage autorisé uniquement sur vos propres réseaux / labs{YELLOW}{BOLD}   *
********************************************************************{RESET}
{CYAN}Mode : Local autonome | Logs : {LOG_FILE}{RESET}
"""
    print(banner)


def get_local_ip() -> str:
    """Détecte l'adresse IP locale de la machine même sans accès Internet."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def ping_host(ip: str, timeout_ms: int = 800) -> tuple[bool, float | None]:
    """Envoie un ping ICMP (multi-OS) et retourne (succès, latence_ms)."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        timeout_sec = max(1, round(timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

    start = time.time()
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        elapsed = (time.time() - start) * 1000
        if res.returncode == 0:
            match = re.search(r"time[=<]\s*([\d.]+)\s*ms", res.stdout, re.IGNORECASE)
            latency = float(match.group(1)) if match else round(elapsed, 2)
            return True, latency
    except Exception:
        pass
    return False, None


def get_arp_table() -> dict[str, str]:
    """Lit la table ARP locale pour associer IP -> adresse MAC."""
    arp_map: dict[str, str] = {}
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            mac_match = re.search(r"(([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})", line)
            if ip_match and mac_match:
                ip = ip_match.group(1)
                mac = mac_match.group(1).lower().replace("-", ":")
                mac = ":".join(part.zfill(2) for part in mac.split(":"))
                if mac != "ff:ff:ff:ff:ff:ff":
                    arp_map[ip] = mac
    except Exception:
        pass
    return arp_map


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Inconnu"


def discover_network() -> list[dict[str, str]]:
    """Découvre les appareils actifs sur le sous-réseau /24 local."""
    local_ip = get_local_ip()
    if local_ip.startswith("127."):
        print(f"{RED}[!] Aucune interface réseau locale active détectée.{RESET}")
        return []

    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    hosts = [str(ip) for ip in network.hosts()]

    print(f"{CYAN}[*] Scan du réseau local {network} en cours...{RESET}")
    active_ips: list[str] = []

    with ThreadPoolExecutor(max_workers=60) as executor:
        results = executor.map(lambda ip: (ip, ping_host(ip, timeout_ms=500)[0]), hosts)
        for ip, is_up in results:
            if is_up:
                active_ips.append(ip)

    arp_table = get_arp_table()
    devices: list[dict[str, str]] = []
    for ip in sorted(active_ips, key=lambda x: tuple(map(int, x.split(".")))):
        devices.append({
            "ip": ip,
            "mac": arp_table.get(ip, "N/A"),
            "hostname": resolve_hostname(ip),
        })
    return devices


def option_wifi_scan() -> None:
    devices = discover_network()
    if not devices:
        return
    print(f"\n{GREEN}{BOLD}[+] {len(devices)} appareil(s) détecté(s) :{RESET}\n")
    print(f"{'IP':<16} | {'MAC':<18} | {'NOM D\'HÔTE'}")
    print("-" * 60)
    for d in devices:
        print(f"{d['ip']:<16} | {d['mac']:<18} | {d['hostname']}")
    logger.info(f"Scan Wi-Fi effectué : {len(devices)} appareil(s) actif(s).")


def load_trusted_devices() -> dict[str, str]:
    if not os.path.exists(TRUSTED_FILE):
        with open(TRUSTED_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, indent=2)
        return {}
    try:
        with open(TRUSTED_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_trusted_devices(trusted: dict[str, str]) -> None:
    with open(TRUSTED_FILE, "w", encoding="utf-8") as f:
        json.dump(trusted, f, indent=2, ensure_ascii=False)


def check_risky_ports(ip: str) -> list[str]:
    open_risks: list[str] = []
    for port, desc in RISKY_PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex((ip, port)) == 0:
                open_risks.append(f"{port} ({desc})")
    return open_risks


def option_security_audit() -> None:
    devices = discover_network()
    if not devices:
        return

    trusted = load_trusted_devices()
    unknown_devices: list[dict[str, str]] = []

    print(f"\n{BOLD}=== AUDIT DE SÉCURITÉ DU RÉSEAU LOCAL ==={RESET}\n")
    for d in devices:
        mac = d["mac"]
        ip = d["ip"]
        is_trusted = mac in trusted
        status = f"{GREEN}[AUTORISÉ: {trusted[mac]}]{RESET}" if is_trusted else f"{RED}[INCONNU / NON AUTORISÉ]{RESET}"
        if not is_trusted and mac != "N/A":
            unknown_devices.append(d)

        risks = check_risky_ports(ip)
        risk_str = f"{RED}Ports ouverts : {', '.join(risks)}{RESET}" if risks else f"{GREEN}Aucun port critique ouvert{RESET}"
        print(f"• {BOLD}{ip:<15}{RESET} | MAC: {mac:<17} | {status} | {risk_str}")

    if unknown_devices:
        choice = input(f"\n{YELLOW}Voulez-vous ajouter les appareils inconnus à '{TRUSTED_FILE}' ? (o/n) : {RESET}").strip().lower()
        if choice == "o":
            for d in unknown_devices:
                label = input(f"  Nom pour {d['ip']} ({d['mac']}) [{d['hostname']}] : ").strip()
                trusted[d["mac"]] = label or d["hostname"]
            save_trusted_devices(trusted)
            print(f"{GREEN}[+] Liste des appareils de confiance mise à jour.{RESET}")
            logger.info("Liste des appareils de confiance mise à jour.")


def test_download_speed() -> None:
    """Mesure approximative du débit descendant via un fichier de test léger."""
    test_url = "https://speed.cloudflare.com/__down?bytes=5000000"
    print(f"\n{CYAN}[*] Test de débit descendant en cours (5 Mo)...{RESET}")
    try:
        start = time.time()
        with urllib.request.urlopen(test_url, timeout=10) as resp:
            data = resp.read()
        duration = time.time() - start
        mbps = (len(data) * 8) / (duration * 1_000_000)
        print(f"{GREEN}[+] Débit descendant estimé : {mbps:.2f} Mbps ({duration:.2f}s){RESET}")
        logger.info(f"Test débit Wi-Fi : {mbps:.2f} Mbps")
    except Exception as e:
        print(f"{RED}[!] Impossible de mesurer le débit (hors ligne ou timeout) : {e}{RESET}")


def load_hosts() -> list[dict[str, str]]:
    if not os.path.exists(HOSTS_FILE):
        default_hosts = [
            {"name": "Routeur Local", "ip": "192.168.1.1"},
            {"name": "Cloudflare DNS", "ip": "1.1.1.1"},
            {"name": "Google DNS", "ip": "8.8.8.8"},
        ]
        with open(HOSTS_FILE, "w", encoding="utf-8") as f:
            json.dump(default_hosts, f, indent=2)
        return default_hosts
    with open(HOSTS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def check_with_retries(ip: str, retries: int = 3) -> tuple[bool, float | None]:
    for _ in range(retries):
        ok, latency = ping_host(ip)
        if ok:
            return True, latency
        time.sleep(0.5)
    return False, None


def option_ping_monitor() -> None:
    test_download_speed()
    hosts = load_hosts()
    down_since: dict[str, datetime] = {}

    print(f"\n{CYAN}[*] Démarrage du Ping Monitor local ({len(hosts)} hôtes) — Ctrl+C pour arrêter{RESET}\n")
    try:
        while True:
            now = datetime.now()
            timestamp = now.strftime("%H:%M:%S")
            for h in hosts:
                name, ip = h["name"], h["ip"]
                is_up, latency = check_with_retries(ip)
                if is_up:
                    if ip in down_since:
                        downtime = int((now - down_since.pop(ip)).total_seconds())
                        msg = f"RETOUR EN LIGNE : {name} ({ip}) après {downtime}s de coupure."
                        print(f"[{timestamp}] {GREEN}{BOLD}[UP] {msg}{RESET}")
                        logger.info(msg)
                    else:
                        print(f"[{timestamp}] {GREEN}[UP]{RESET}   {name:<18} ({ip:<15}) — {latency} ms")
                else:
                    if ip not in down_since:
                        down_since[ip] = now
                        msg = f"ALERTE PANNE : {name} ({ip}) ne répond plus !"
                        print(f"[{timestamp}] {RED}{BOLD}[DOWN] {msg}{RESET}")
                        logger.warning(msg)
                    else:
                        elapsed = int((now - down_since[ip]).total_seconds())
                        print(f"[{timestamp}] {RED}[DOWN]{RESET} {name:<18} ({ip:<15}) — hors ligne depuis {elapsed}s")
            print("-" * 65)
            time.sleep(10)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Surveillance arrêtée par l'utilisateur.{RESET}")


def main() -> None:
    while True:
        print_banner()
        print("Choisissez une option :\n")
        print(f"  {CYAN}[1]{RESET} Scanner les appareils sur le Wi-Fi (IP, MAC, Nom)")
        print(f"  {CYAN}[2]{RESET} Audit Sécurité (Trusted Devices & Ports à risque)")
        print(f"  {CYAN}[3]{RESET} Diagnostic Débit Wi-Fi & Ping Monitor Local")
        print(f"  {RED}[0]{RESET} Quitter\n")

        choice = input(f"{YELLOW}{BOLD}Votre choix [0-3] : {RESET}").strip()

        if choice == "1":
            option_wifi_scan()
        elif choice == "2":
            option_security_audit()
        elif choice == "3":
            option_ping_monitor()
        elif choice == "0":
            print(f"{GREEN}Au revoir !{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}Choix invalide.{RESET}")

        input(f"\n{CYAN}Appuyez sur Entrée pour revenir au menu...{RESET}")


if __name__ == "__main__":
    main()








