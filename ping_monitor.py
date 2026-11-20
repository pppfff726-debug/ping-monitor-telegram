from __future__ import annotations

import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import platform
import re
import socket
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import requests
from dotenv import load_dotenv

# Active les couleurs ANSI sur Windows CMD
if os.name == "nt":
    os.system("")

# Chargement des variables secrètes depuis .env
load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()


# --- COULEURS ANSI POUR TERMINAL PRO ---
class Color:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# Ports connus pour risques sécurité ou backdoors
RISKY_PORTS = {
    21: ("FTP (Non chiffré)", "MEDIUM"),
    23: ("Telnet (Danger - Clear text)", "HIGH"),
    135: ("RPC Windows", "MEDIUM"),
    139: ("NetBIOS", "MEDIUM"),
    445: ("SMB (Cible Ransomware/WannaCry)", "HIGH"),
    3389: ("RDP (Cible Brute-Force)", "HIGH"),
    4444: ("Metasploit / Backdoor", "CRITICAL"),
    5555: ("Android ADB exposé", "HIGH"),
    5900: ("VNC Contrôle à distance", "HIGH"),
    6667: ("IRC (Botnet C&C fréquent)", "CRITICAL"),
    8080: ("Proxy HTTP alternatif", "LOW"),
    31337: ("Back Orifice Trojan", "CRITICAL"),
}

HOSTS_FILE = "hosts.json"
TRUSTED_FILE = "trusted_devices.json"
LOG_FILE = "monitor.log"
DEFAULT_RETRIES = 3


def setup_logger() -> logging.Logger:
    """Configure les logs rotatifs dans monitor.log (1 Mo max, 3 backups)."""
    logger = logging.getLogger("NetBasicsPro")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


logger = setup_logger()


def send_telegram_alert(message: str) -> bool:
    """Envoie une alerte Telegram sans jamais faire crasher le programme."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or "your_bot_token" in TELEGRAM_BOT_TOKEN:
        logger.warning("Alerte Telegram ignorée : TELEGRAM_BOT_TOKEN ou TELEGRAM_CHAT_ID manquant dans .env")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}

    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            logger.info(f"Alerte Telegram envoyée : {message}")
            return True
        logger.error(f"Erreur API Telegram ({response.status_code}) : {response.text}")
        return False
    except requests.RequestException as exc:
        logger.error(f"Échec connexion Telegram : {exc}")
        return False


def format_duration(seconds: float) -> str:
    """Formate une durée en secondes vers 'Xh Ym Zs'."""
    total = int(seconds)
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def print_banner() -> None:
    """Affiche la bannière pro BONJOUR entourée d'étoiles."""
    os.system("cls" if os.name == "nt" else "clear")
    stars = f"{Color.YELLOW}{Color.BOLD}" + "*" * 66 + f"{Color.RESET}"
    empty_star_line = f"{Color.YELLOW}{Color.BOLD}*{Color.RESET}" + " " * 64 + f"{Color.YELLOW}{Color.BOLD}*{Color.RESET}"

    bonjour_art = [
        "  ____   ___  _   _     _  ___  _   _ ____  ",
        " | __ ) / _ \\| \\ | |   | |/ _ \\| | | |  _ \\ ",
        " |  _ \\| | | |  \\| |_  | | | | | | | | |_) |",
        " | |_) | |_| | |\\  | |_| | |_| | |_| |  _ < ",
        " |____/ \\___/|_| \\_|\\___/ \\___/ \\___/|_| \\_\\",
    ]

    print(stars)
    print(empty_star_line)
    for line in bonjour_art:
        centered = line.center(64)
        print(f"{Color.YELLOW}{Color.BOLD}*{Color.CYAN}{centered}{Color.YELLOW}*{Color.RESET}")
    print(empty_star_line)
    subtitle = "NETBASICS PRO v1 | Scanner Réseau, Sécurité & Wi-Fi".center(64)
    print(f"{Color.YELLOW}{Color.BOLD}*{Color.GREEN}{subtitle}{Color.YELLOW}*{Color.RESET}")
    legal = "Usage autorisé uniquement sur vos propres réseaux / labs".center(64)
    print(f"{Color.YELLOW}{Color.BOLD}*{Color.DIM}{legal}{Color.RESET}{Color.YELLOW}{Color.BOLD}*{Color.RESET}")
    print(stars)

    tg_status = (
        f"{Color.GREEN}Actif ✅{Color.RESET}"
        if TELEGRAM_BOT_TOKEN and "your_bot_token" not in TELEGRAM_BOT_TOKEN
        else f"{Color.YELLOW}Non configuré (.env){Color.RESET}"
    )
    print(f"{Color.DIM}Statut Bot Telegram : {tg_status} {Color.DIM}| Logs : {LOG_FILE}{Color.RESET}\n")


def get_local_ip() -> str:
    """Détecte l'IP locale sur le réseau actuel (fonctionne même sans accès Internet)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except Exception:
        # Fallback hors-ligne (lab / routeur sans Internet)
        try:
            hostname_ip = socket.gethostbyname(socket.gethostname())
            if not hostname_ip.startswith("127."):
                return hostname_ip
        except Exception:
            pass
        return "127.0.0.1"
    finally:
        sock.close()


def get_arp_table() -> dict[str, str]:
    """Récupère les adresses MAC connues depuis la table ARP du système."""
    mac_map = {}
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, timeout=3)
        for line in output.splitlines():
            ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line) or re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            mac_match = re.search(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}", line)
            if ip_match and mac_match:
                mac_map[ip_match.group(1)] = mac_match.group(0).lower()
    except Exception:
        pass
    return mac_map


def ping_host(ip: str, timeout_sec: int = 1) -> bool:
    """Envoie un ping compatible macOS, Windows et Linux."""
    system = platform.system().lower()
    timeout_ms = timeout_sec * 1000

    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif system == "darwin":  # macOS
        command = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:  # Linux
        command = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_sec + 1)
        if system == "windows":
            return result.returncode == 0 and "TTL=" in result.stdout.upper()
        return result.returncode == 0
    except Exception:
        return False


def resolve_hostname(ip: str) -> str:
    """Résout le nom d'hôte de l'appareil."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "Appareil inconnu"


def load_and_validate_hosts(filepath: str = HOSTS_FILE) -> list[dict]:
    """Charge et valide les entrées (nom + IP valide) depuis hosts.json."""
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            print(f"{Color.RED}Erreur : {filepath} doit contenir une liste JSON.{Color.RESET}")
            return []

        valid_hosts = []
        for entry in data:
            if not isinstance(entry, dict) or "name" not in entry or "ip" not in entry:
                logger.warning(f"Entrée ignorée dans {filepath} (champs manquants) : {entry}")
                continue
            try:
                ipaddress.ip_address(entry["ip"])
                valid_hosts.append(entry)
            except ValueError:
                print(f"{Color.RED}IP invalide ignorée dans {filepath} : {entry['ip']}{Color.RESET}")
                logger.error(f"IP invalide dans {filepath} : {entry['ip']}")
        return valid_hosts
    except json.JSONDecodeError as exc:
        print(f"{Color.RED}Erreur de syntaxe JSON dans {filepath} : {exc}{Color.RESET}")
        return []


def load_json(filepath: str, default):
    if not os.path.exists(filepath):
        return default
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(filepath: str, data) -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ==============================================================================
# CHOIX 1 : SCAN DES APPAREILS SUR LE RÉSEAU WI-FI
# ==============================================================================
def choice_1_scan_devices() -> list[dict]:
    print(f"\n{Color.CYAN}{Color.BOLD}=== [1] SCAN DES APPAREILS DU RÉSEAU WI-FI ==={Color.RESET}")
    local_ip = get_local_ip()
    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    all_ips = [str(ip) for ip in network.hosts()]

    print(f"{Color.DIM}Votre IP locale : {local_ip} | Réseau ciblé : {network}{Color.RESET}")
    print(f"{Color.YELLOW}⏳ Scan Ping Sweep en cours ({len(all_ips)} adresses)...{Color.RESET}\n")

    start_time = time.time()
    discovered = []

    def check_ip(ip: str):
        if ping_host(ip, timeout_sec=1):
            return {"name": resolve_hostname(ip), "ip": ip}
        return None

    with ThreadPoolExecutor(max_workers=60) as executor:
        for res in executor.map(check_ip, all_ips):
            if res:
                discovered.append(res)

    arp_table = get_arp_table()
    discovered.sort(key=lambda h: ipaddress.IPv4Address(h["ip"]))
    duration = round(time.time() - start_time, 2)

    print(f"{Color.GREEN}{Color.BOLD}✅ Scan terminé en {duration}s : {len(discovered)} appareil(s) détecté(s) !{Color.RESET}\n")
    print(f"{Color.BOLD}{'IP':<16} | {'ADRESSE MAC':<19} | {'NOM DE L\'APPAREIL'}{Color.RESET}")
    print("-" * 66)

    for host in discovered:
        mac = arp_table.get(host["ip"], "N/A (Local/Masqué)")
        host["mac"] = mac
        tag = f" {Color.CYAN}(Vous){Color.RESET}" if host["ip"] == local_ip else ""
        print(f"{Color.GREEN}{host['ip']:<16}{Color.RESET} | {Color.YELLOW}{mac:<19}{Color.RESET} | {host['name']}{tag}")

    save_json(HOSTS_FILE, discovered)
    logger.info(f"Scan réseau {network} terminé : {len(discovered)} appareils trouvés en {duration}s.")
    print(f"\n{Color.DIM}💾 Liste sauvegardée dans {HOSTS_FILE}.{Color.RESET}")
    return discovered


# ==============================================================================
# CHOIX 2 : AUDIT SÉCURITÉ (TRUSTED DEVICES & PORTS À RISQUE / BACKDOORS)
# ==============================================================================
def scan_risky_ports_parallel(ip: str) -> list[tuple[int, str, str]]:
    """Scanne en parallèle les ports à risque et backdoors sur une IP."""
    def check_single_port(item):
        port, (desc, severity) = item
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.35)
        try:
            if sock.connect_ex((ip, port)) == 0:
                return (port, desc, severity)
        except Exception:
            pass
        finally:
            sock.close()
        return None

    findings = []
    with ThreadPoolExecutor(max_workers=len(RISKY_PORTS)) as executor:
        for res in executor.map(check_single_port, RISKY_PORTS.items()):
            if res:
                findings.append(res)
    findings.sort(key=lambda x: x[0])
    return findings


def choice_2_security_audit() -> None:
    print(f"\n{Color.MAGENTA}{Color.BOLD}=== [2] AUDIT SÉCURITÉ : TRUSTED DEVICES & PORTS À RISQUE ==={Color.RESET}")
    hosts = load_and_validate_hosts(HOSTS_FILE)
    if not hosts:
        print(f"{Color.YELLOW}Aucun appareil en mémoire. Lancement d'un scan réseau rapide d'abord...{Color.RESET}")
        hosts = choice_1_scan_devices()

    trusted_list = load_json(TRUSTED_FILE, [])
    trusted_ips = {item["ip"] for item in trusted_list}
    trusted_macs = {item.get("mac") for item in trusted_list if item.get("mac") and item.get("mac") != "N/A (Local/Masqué)"}

    local_ip = get_local_ip()
    untrusted_found = []
    print(f"\n{Color.YELLOW}🛡️  Vérification de confiance et scan rapide des ports critiques...{Color.RESET}\n")

    for host in hosts:
        ip = host["ip"]
        mac = host.get("mac", "N/A")
        name = host["name"]

        is_trusted = (ip == local_ip) or (ip in trusted_ips) or (mac in trusted_macs)
        if not is_trusted:
            untrusted_found.append(f"{name} ({ip})")

        trust_badge = (
            f"{Color.GREEN}{Color.BOLD}[TRUSTED ✅]{Color.RESET}"
            if is_trusted
            else f"{Color.RED}{Color.BOLD}[NON VÉRIFIÉ ⚠️]{Color.RESET}"
        )

        print(f"🔎 {Color.BOLD}{ip:<15}{Color.RESET} ({name}) — {trust_badge}")
        findings = scan_risky_ports_parallel(ip)

        if not findings:
            print(f"   {Color.GREEN}└─ Aucun port critique ou backdoor détecté (Clean).{Color.RESET}")
        else:
            for port, desc, severity in findings:
                sev_color = Color.RED if severity in ("HIGH", "CRITICAL") else Color.YELLOW
                print(f"   {sev_color}└─ [ALERTE {severity}] Port {port} ouvert : {desc}{Color.RESET}")
                logger.warning(f"Audit Sécurité {ip} : Port {port} ({desc}) ouvert [{severity}]")

    if untrusted_found:
        alert_msg = f"🛡️ AUDIT SÉCURITÉ : {len(untrusted_found)} appareil(s) non vérifié(s) sur le Wi-Fi : {', '.join(untrusted_found)}"
        send_telegram_alert(alert_msg)

    print("\n" + "-" * 66)
    ans = input(f"{Color.CYAN}Voulez-vous marquer tous les appareils actuels comme TRUSTED ? (o/n) : {Color.RESET}").strip().lower()
    if ans in ("o", "oui", "y", "yes"):
        save_json(TRUSTED_FILE, hosts)
        logger.info(f"{len(hosts)} appareils enregistrés comme TRUSTED.")
        print(f"{Color.GREEN}✅ Appareils enregistrés dans {TRUSTED_FILE} comme appareils de confiance !{Color.RESET}")


# ==============================================================================
# CHOIX 3 : DÉBIT WI-FI, BANDE FRÉQUENCE & PING MONITOR (AVEC TELEGRAM & RETRIES)
# ==============================================================================
def check_wifi_band_and_speed() -> None:
    print(f"\n{Color.BLUE}{Color.BOLD}=== [3] DIAGNOSTIC WI-FI (BANDE / DÉBIT) & PING MONITOR ==={Color.RESET}")

    print(f"\n{Color.CYAN}📡 Informations Interface Wi-Fi :{Color.RESET}")
    system = platform.system().lower()
    if system == "darwin":
        try:
            net_out = subprocess.check_output(["networksetup", "-getairportnetwork", "en0"], text=True, timeout=3).strip()
            print(f"   • Réseau connecté : {Color.GREEN}{net_out}{Color.RESET}")
            sp_out = subprocess.check_output(["system_profiler", "SPAirPortDataType"], text=True, timeout=5)
            for line in sp_out.splitlines():
                clean = line.strip()
                if any(k in clean for k in ["Channel:", "PHY Mode:", "Signal / Noise:", "Transmit Rate:"]):
                    print(f"   • {Color.YELLOW}{clean}{Color.RESET}")
        except Exception:
            print(f"   • {Color.DIM}Détails matériels Wi-Fi non disponibles (permission macOS).{Color.RESET}")
    else:
        print(f"   • IP Locale : {Color.GREEN}{get_local_ip()}{Color.RESET}")

    print(f"\n{Color.CYAN}⏱️  Test de latence & stabilité (5 pings vers 8.8.8.8) :{Color.RESET}")
    latencies = []
    for _ in range(5):
        t0 = time.time()
        if ping_host("8.8.8.8", timeout_sec=2):
            latencies.append((time.time() - t0) * 1000)
        time.sleep(0.2)

    if latencies:
        avg_ms = round(sum(latencies) / len(latencies), 1)
        loss = int(((5 - len(latencies)) / 5) * 100)
        lat_color = Color.GREEN if avg_ms < 60 else (Color.YELLOW if avg_ms < 120 else Color.RED)
        print(f"   • Latence moyenne : {lat_color}{avg_ms} ms{Color.RESET} | Perte de paquets : {loss}%")
    else:
        print(f"   • {Color.RED}Hors ligne : impossible de joindre Internet (8.8.8.8).{Color.RESET}")

    print(f"\n{Color.CYAN}🚀 Test du débit Wi-Fi (Download Speed - 2 Mo)...{Color.RESET}")
    try:
        test_url = "https://speed.cloudflare.com/__down?bytes=2000000"  # 2 Mo (économe en data)
        req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
        t_start = time.time()
        with urllib.request.urlopen(req, timeout=8) as response:
            data = response.read()
        elapsed = time.time() - t_start
        mbps = round((len(data) * 8) / (elapsed * 1_000_000), 2)
        speed_color = Color.GREEN if mbps > 20 else (Color.YELLOW if mbps > 5 else Color.RED)
        print(f"   • Débit descendant estimé : {speed_color}{Color.BOLD}{mbps} Mbps{Color.RESET}")
    except Exception:
        print(f"   • {Color.YELLOW}Test de débit indisponible (pas d'accès Internet).{Color.RESET}")


def choice_3_wifi_and_ping_monitor() -> None:
    check_wifi_band_and_speed()

    print("\n" + "-" * 66)
    start_mon = input(f"{Color.CYAN}Lancer le Ping Monitor continu avec alertes Telegram ? (o/n) : {Color.RESET}").strip().lower()
    if start_mon not in ("o", "oui", "y", "yes"):
        return

    hosts = load_and_validate_hosts(HOSTS_FILE)
    if not hosts:
        hosts = [{"name": "Localhost", "ip": "127.0.0.1"}, {"name": "Google DNS", "ip": "8.8.8.8"}]

    interval = 15
    retries = DEFAULT_RETRIES
    last_states: dict[str, str] = {}
    fail_counts: dict[str, int] = {h["ip"]: 0 for h in hosts}
    down_since: dict[str, float] = {}
    cycle = 0

    print(f"\n{Color.GREEN}📡 Ping Monitor actif ({len(hosts)} hôtes | cycle {interval}s | {retries} retries). Ctrl+C pour arrêter.{Color.RESET}\n")
    logger.info(f"Démarrage Ping Monitor ({len(hosts)} hôtes, interval={interval}s, retries={retries})")

    try:
        while True:
            cycle += 1
            up_count = 0

            for host in hosts:
                name, ip = host["name"], host["ip"]
                is_up = ping_host(ip, timeout_sec=2)
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                short_ts = datetime.now().strftime("%H:%M:%S")

                if is_up:
                    fail_counts[ip] = 0
                    up_count += 1
                    prev_state = last_states.get(ip)

                    if prev_state == "DOWN":
                        downtime = format_duration(time.time() - down_since.get(ip, time.time()))
                        print(f"[{short_ts}] {name} ({ip}) -> {Color.GREEN}RECOVERED ✅{Color.RESET} (panne: {downtime})")
                        logger.info(f"RECOVERED: {name} ({ip}) après {downtime}")
                        send_telegram_alert(f"✅ RECOVERED: {name} ({ip}) is back UP after {downtime}")
                    elif prev_state is None:
                        print(f"[{short_ts}] {name} ({ip}) -> {Color.GREEN}UP ✅{Color.RESET}")
                        logger.info(f"État initial UP: {name} ({ip})")

                    last_states[ip] = "UP"
                else:
                    fail_counts[ip] = fail_counts.get(ip, 0) + 1
                    if fail_counts[ip] >= retries and last_states.get(ip) != "DOWN":
                        last_states[ip] = "DOWN"
                        down_since[ip] = time.time()
                        print(f"[{short_ts}] {name} ({ip}) -> {Color.RED}DOWN ❌{Color.RESET} (après {retries} échecs)")
                        logger.warning(f"ALERT DOWN: {name} ({ip}) depuis {now_str}")
                        send_telegram_alert(f"🚨 ALERT: {name} ({ip}) is DOWN since {now_str}")

            if cycle % 5 == 0:
                short_ts = datetime.now().strftime("%H:%M:%S")
                print(f"{Color.DIM}[{short_ts}] Résumé (Cycle {cycle}) : {up_count} UP | {len(hosts) - up_count} DOWN{Color.RESET}")

            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Arrêt du Ping Monitor par l'utilisateur.")
        print(f"\n{Color.YELLOW}⏹️  Ping Monitor arrêté. Retour au menu...{Color.RESET}")


# ==============================================================================
# MENU PRINCIPAL
# ==============================================================================
def main() -> None:
    while True:
        print_banner()
        print(f"{Color.BOLD}Choisissez une option :{Color.RESET}\n")
        print(f"  {Color.CYAN}{Color.BOLD}[1]{Color.RESET} 🔍 Scanner les appareils sur le Wi-Fi (IP, MAC, Nom)")
        print(f"  {Color.MAGENTA}{Color.BOLD}[2]{Color.RESET} 🛡️  Audit Sécurité (Trusted Devices & Ports à risque)")
        print(f"  {Color.BLUE}{Color.BOLD}[3]{Color.RESET} 🚀 Diagnostic Débit Wi-Fi / Bande & Ping Monitor Telegram")
        print(f"  {Color.RED}{Color.BOLD}[0]{Color.RESET} ❌ Quitter\n")

        choice = input(f"{Color.YELLOW}{Color.BOLD}Votre choix [0-3] : {Color.RESET}").strip()

        if choice == "1":
            choice_1_scan_devices()
        elif choice == "2":
            choice_2_security_audit()
        elif choice == "3":
            choice_3_wifi_and_ping_monitor()
        elif choice == "0":
            print(f"\n{Color.GREEN}Au revoir ! À bientôt 👋{Color.RESET}")
            break
        else:
            print(f"{Color.RED}Choix invalide. Tapez 1, 2, 3 ou 0.{Color.RESET}")

        input(f"\n{Color.DIM}Appuyez sur Entrée pour revenir au menu...{Color.RESET}")


if __name__ == "__main__":
    main()







