#!/usr/bin/env python3

import os
import re
import sys
import json
import shlex
import socket
import subprocess
import ipaddress
from datetime import datetime
from pathlib import Path

CONFIG_PATH = Path("/etc/secwizard/config.json")
BACKUP_DIR = Path("/var/backups/secwizard")
STATE_DIR = Path("/var/lib/secwizard")
EXAMPLES_DIR = Path("/etc/secwizard/examples")
PKI_DIR = Path("/etc/secwizard/pki")

DEFAULT_CONFIG = {
    "version": 2,
    "firewall": {
        "enabled": True,
        "ssh_port": 22,
        "ipv6": True,
        "default_input_policy": "DROP",
        "allow_established": True,
        "allow_loopback": True,
        "allow_icmp": True,
        "docker_aware": True,
        "allow_host_hairpin": True,
        "rescue_seconds": 90,
        "global_whitelist": [],
        "per_port_whitelist": {},
        "open_ports": ["22/tcp"],
        "blocked_ports": [],
        "lb_ip": None,
        "web_role": None
    },
    "web": {
        "is_webserver": None,
        "selfsigned_cert": None,
        "cert_cn": None,
        "cert_days": 3650
    },
    "ssh": {
        "create_admin": None,
        "admin_user": None,
        "admin_keys": [],
        "password_auth": None,
        "disable_root_login": None,
        "enable_totp": None,
        "enforce_2fa": None
    },
    "updates": {
        "enable": True,
        "weekday": "Mon",
        "update_hour": 4,
        "reboot_hour": 5,
        "reboot_if_kernel_updated": True
    },
    "fail2ban": {"enable": None},
    "selinux": {"manage": None, "enforcing": None},
    "special_ports": []
}

def _decode_bytes(data: bytes) -> str:
    if data is None:
        return ""
    for enc in (getattr(sys.stdin, "encoding", None), "utf-8", "latin-1"):
        if not enc:
            continue
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="ignore")

def read_line(prompt: str = "") -> str:
    if prompt:
        try:
            sys.stdout.write(prompt); sys.stdout.flush()
        except Exception:
            pass
    try:
        data = sys.stdin.buffer.readline()
    except Exception:
        try:
            return input(prompt)
        except Exception:
            return ""
    return _decode_bytes(data).rstrip("\r\n")

def ensure_root():
    if os.geteuid() != 0:
        print("[FATAL] Dieses Skript muss als root ausgeführt werden.")
        sys.exit(1)

def run(cmd: str, check=True, capture_output=True, text=True):
    try:
        return subprocess.run(shlex.split(cmd), check=check,
                              capture_output=capture_output, text=text)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Befehl fehlgeschlagen: {cmd}\nExit {e.returncode}\nSTDERR: {e.stderr}")
        if check:
            sys.exit(e.returncode)
        return e

def run_sh(cmd: str, check=True):
    try:
        return subprocess.run(cmd, shell=True, check=check,
                              capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Shell-Befehl fehlgeschlagen: {cmd}\nExit {e.returncode}\nSTDERR: {e.stderr}")
        if check:
            sys.exit(e.returncode)
        return e

def shutil_which(cmd: str) -> bool:
    from shutil import which as _which
    return _which(cmd) is not None

def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                cfg = json.load(f)

            for top, sub in DEFAULT_CONFIG.items():
                if top not in cfg:
                    cfg[top] = json.loads(json.dumps(sub))
                elif isinstance(sub, dict):
                    for k, v in sub.items():
                        cfg[top].setdefault(k, v)
            return cfg
        except Exception as e:
            print(f"[WARN] Konnte Konfig nicht lesen, verwende Defaults. Fehler: {e}")
    return json.loads(json.dumps(DEFAULT_CONFIG))

def save_config(cfg: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix('.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.replace(tmp, CONFIG_PATH)
    print(f"[OK] Konfiguration gespeichert: {CONFIG_PATH}")

def backup_file(path: Path):
    if not path.exists():
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    dst = BACKUP_DIR / f"{path.name}.{ts}.bak"
    import shutil
    shutil.copy2(path, dst)
    print(f"[OK] Backup erstellt: {dst}")

def detect_os():
    data = {}
    try:
        with open('/etc/os-release', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if '=' in line:
                    k, v = line.split('=', 1)
                    data[k] = v.strip('"')
    except FileNotFoundError:
        pass
    id_ = data.get('ID', '').lower()
    like = data.get('ID_LIKE', '').lower()
    if any(x in (id_, like) for x in ['rhel', 'fedora', 'centos', 'almalinux', 'rocky']):
        family = 'rhel'
    elif any(x in (id_, like) for x in ['debian', 'ubuntu']):
        family = 'debian'
    else:
        family = 'unknown'
    version_id = data.get('VERSION_ID', '')
    return family, data.get('PRETTY_NAME', id_ or 'unknown'), version_id, id_

def ssh_service_name() -> str:
    for name in ("sshd", "ssh"):
        res = run(f"systemctl list-unit-files {name}.service", check=False)
        if res.returncode == 0 and f"{name}.service" in (res.stdout or ""):
            return name
    return "sshd"

def restart_sshd():
    name = ssh_service_name()
    res = run(f"systemctl restart {name}", check=False)
    if res.returncode != 0 and name == "sshd":

        run("systemctl restart ssh", check=False)

def _apt_update_once():
    if getattr(_apt_update_once, "_done", False):
        return
    run("apt-get update", check=False)
    _apt_update_once._done = True

def apt_install(pkgs: list, optional: bool = False):
    if not pkgs:
        return
    _apt_update_once()
    pkg_str = " ".join(shlex.quote(p) for p in pkgs)
    res = run(f"env DEBIAN_FRONTEND=noninteractive apt-get -y install {pkg_str}",
              check=False)
    if res.returncode != 0 and not optional:
        print(f"[WARN] apt-get install fehlgeschlagen für: {pkg_str}")

def dnf_install(pkgs: list, optional: bool = False):
    if not pkgs:
        return
    pkg_str = " ".join(shlex.quote(p) for p in pkgs)

    cmd_bin = 'dnf' if shutil_which('dnf') else 'yum'
    res = run(f"{cmd_bin} -y install {pkg_str}", check=False)
    if res.returncode != 0 and not optional:
        print(f"[WARN] {cmd_bin} install fehlgeschlagen für: {pkg_str}")

def _cmp_version(a: str, b: str) -> int:
    def parts(x):
        out = []
        for s in x.split('.'):
            try: out.append(int(s))
            except ValueError: out.append(0)
        return out
    pa, pb = parts(a), parts(b)
    if pa > pb: return 1
    if pa < pb: return -1
    return 0

def detect_iptables_backend() -> str:
    if not shutil_which('iptables'):
        return 'unknown'
    res = run("iptables --version", check=False)
    out = (res.stdout or '') + (res.stderr or '')
    if '(nf_tables)' in out: return 'nft'
    if '(legacy)' in out:    return 'legacy'
    return 'unknown'

def detect_nftables_service_active() -> bool:
    res = run("systemctl is-active nftables.service", check=False)
    return (res.stdout or '').strip() == 'active'

def stop_conflicting_firewalls(family: str):

    res = run("systemctl is-enabled firewalld", check=False)
    if res.returncode == 0:
        print("[INFO] firewalld ist aktiv → wird gestoppt, disabled und maskiert.")
        run("systemctl stop firewalld", check=False)
        run("systemctl disable firewalld", check=False)
        run("systemctl mask firewalld", check=False)

    if family == 'debian':
        res = run("systemctl is-enabled ufw", check=False)
        if res.returncode == 0:
            print("[INFO] ufw ist aktiv → wird gestoppt und disabled.")
            run("systemctl stop ufw", check=False)
            run("systemctl disable ufw", check=False)

    if detect_nftables_service_active():
        print("[INFO] nftables.service ist aktiv → wird gestoppt und disabled,")
        print("       damit iptables-persistent / iptables-services exklusiv lädt.")
        run("systemctl stop nftables.service", check=False)
        run("systemctl disable nftables.service", check=False)

def ensure_base_packages(family: str, version_id: str, distro_id: str):
    print("\n[BOOTSTRAP] Prüfe / installiere Basispakete für Firewall-Verwaltung…")

    if family == 'debian':

        pkgs = []
        if not shutil_which('iptables') or not shutil_which('iptables-save'):
            pkgs.append('iptables')
        if not shutil_which('ip6tables'):
            pkgs.append('iptables')

        if not Path('/etc/iptables').exists() and not shutil_which('netfilter-persistent'):
            pkgs += ['iptables-persistent', 'netfilter-persistent']

        for tool, pkg in (('conntrack', 'conntrack'),
                          ('openssl', 'openssl'),
                          ('curl', 'curl')):
            if not shutil_which(tool):
                pkgs.append(pkg)

        if 'iptables-persistent' in pkgs:
            run("bash -c \"echo iptables-persistent iptables-persistent/autosave_v4 boolean false | debconf-set-selections\"", check=False)
            run("bash -c \"echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections\"", check=False)
        if pkgs:
            apt_install(sorted(set(pkgs)))
        else:
            print("[OK] Alle Basispakete bereits vorhanden.")

    elif family == 'rhel':

        major = version_id.split('.')[0] if version_id else ''

        dnf_install(['epel-release'], optional=True)
        pkgs = []
        if not shutil_which('iptables') or not shutil_which('iptables-save'):

            if major and int(major) >= 8:
                pkgs.append('iptables-nft')
            else:
                pkgs.append('iptables')
        if not shutil_which('ip6tables'):
            pkgs.append('iptables-nft' if (major and int(major) >= 8) else 'iptables-ipv6')

        if not Path('/usr/lib/systemd/system/iptables.service').exists():
            pkgs.append('iptables-services')

        for tool, pkg in (('openssl', 'openssl'),
                          ('curl', 'curl')):
            if not shutil_which(tool):
                pkgs.append(pkg)
        if pkgs:
            dnf_install(sorted(set(pkgs)))
        else:
            print("[OK] Alle Basispakete bereits vorhanden.")
    else:
        print("[WARN] Unbekannte OS-Familie – kein automatischer Paket-Bootstrap.")

    stop_conflicting_firewalls(family)

    missing = [c for c in ('iptables', 'ip6tables', 'iptables-save', 'iptables-restore')
               if not shutil_which(c)]
    if missing:
        print(f"[FATAL] Folgende Tools fehlen weiterhin: {', '.join(missing)}")
        print("        Bitte manuell installieren und erneut starten.")
        sys.exit(1)

def setup_iptables_backend(family: str):
    backend = detect_iptables_backend()
    print(f"[INFO] iptables-Backend aktuell: {backend}")
    if backend == 'unknown':
        return

    if family == 'debian':

        if not Path('/usr/sbin/iptables-nft').exists() or not Path('/usr/sbin/iptables-legacy').exists():
            apt_install(['iptables'], optional=True)

        prefer = 'nft'
        if docker_installed():
            res = run("docker --version", check=False)
            ver_match = re.search(r'(\d+)\.(\d+)\.(\d+)', res.stdout or '')
            if ver_match:
                major = int(ver_match.group(1))
                minor = int(ver_match.group(2))
                if major < 20 or (major == 20 and minor < 10):
                    prefer = 'legacy'
                    print("[INFO] Älteres Docker erkannt – empfehle legacy-Backend.")
            else:
                print("[INFO] Docker installiert – nft-Backend funktioniert mit Docker ≥ 20.10.")

        if backend != prefer:
            print(f"[INFO] Wechsle iptables-Backend: {backend} → {prefer}")
            for tool in ('iptables', 'ip6tables', 'arptables', 'ebtables'):
                target = f"/usr/sbin/{tool}-{prefer}"
                if Path(target).exists():
                    run(f"update-alternatives --set {tool} {target}", check=False)
            new_backend = detect_iptables_backend()
            print(f"[INFO] iptables-Backend jetzt: {new_backend}")

    elif family == 'rhel':

        if backend == 'legacy':
            print("[INFO] RHEL/Alma mit legacy-iptables – ungewöhnlich, aber unterstützt.")

def iptables_cmds():
    v4 = 'iptables'; v6 = 'ip6tables'
    missing = [c for c in (v4, v6) if not shutil_which(c)]
    if missing:
        print(f"[WARN] '{', '.join(missing)}' nicht gefunden – versuche Auto-Install.")
        family, _pretty, version_id, distro_id = detect_os()
        ensure_base_packages(family, version_id, distro_id)
    for c in (v4, v6):
        if not shutil_which(c):
            print(f"[FATAL] '{c}' nicht gefunden. Auto-Install hat nicht funktioniert.")
            sys.exit(1)
    return v4, v6

def docker_installed() -> bool:
    return shutil_which('docker') and Path('/var/run/docker.sock').exists()

def ensure_docker_user_chain(v4='iptables', v6='ip6tables'):
    res = run(f"{v4} -S DOCKER-USER", check=False)
    if res.returncode != 0:
        run(f"{v4} -N DOCKER-USER", check=False)
        run(f"{v4} -I FORWARD -j DOCKER-USER", check=False)
    res6 = run(f"{v6} -S DOCKER-USER", check=False)
    if res6.returncode != 0:
        run(f"{v6} -N DOCKER-USER", check=False)
        run(f"{v6} -I FORWARD -j DOCKER-USER", check=False)

def iptables_save_persist(family: str):
    if family == 'rhel':
        Path('/etc/sysconfig').mkdir(parents=True, exist_ok=True)
        with open('/etc/sysconfig/iptables', 'w') as f:
            f.write(run('iptables-save').stdout)
        with open('/etc/sysconfig/ip6tables', 'w') as f:
            f.write(run('ip6tables-save').stdout)
        run("systemctl enable iptables", check=False)
        run("systemctl enable ip6tables", check=False)
        run("systemctl restart iptables", check=False)
        run("systemctl restart ip6tables", check=False)
        print("[OK] Regeln gespeichert (RHEL/Alma): /etc/sysconfig/iptables{,6}")
    elif family == 'debian':
        Path('/etc/iptables').mkdir(parents=True, exist_ok=True)
        with open('/etc/iptables/rules.v4', 'w') as f:
            f.write(run('iptables-save').stdout)
        with open('/etc/iptables/rules.v6', 'w') as f:
            f.write(run('ip6tables-save').stdout)

        run("systemctl enable netfilter-persistent", check=False)
        run("systemctl restart netfilter-persistent", check=False)
        print("[OK] Regeln gespeichert (Debian/Ubuntu): /etc/iptables/rules.v4/.v6")
    else:
        print("[WARN] Unbekannte OS-Familie - Persistenz muss manuell erfolgen.")

def parse_portdef(s: str):
    s = s.strip().lower()
    if '/' in s:
        port, proto = s.split('/', 1)
    else:
        port, proto = s, 'tcp'
    return int(port), proto

def canonicalize_spec(spec: str, default_proto: str = 'tcp') -> str:
    s = spec.strip().lower()
    if '/' in s:
        p, pr = s.split('/', 1)
        return f"{int(p)}/{pr}"
    return f"{int(s)}/{default_proto}"

def ensure_spec_interactive(spec: str) -> str:
    s = spec.strip().lower()
    if '/' in s:
        p, pr = s.split('/', 1)
        return f"{int(p)}/{pr}"
    pr = ask_choice("Protokoll wählen:", ["tcp", "udp"])
    return f"{int(s)}/{pr}"

def normalize_config(cfg: dict):
    fw = cfg.setdefault('firewall', {})
    fw.setdefault('allow_icmp', True)
    open_raw = [canonicalize_spec(x) for x in fw.get('open_ports', [])]
    blocked_raw = [canonicalize_spec(x) for x in fw.get('blocked_ports', [])]
    blocked_set = set(blocked_raw)
    open_set = set(p for p in open_raw if p not in blocked_set)
    ppw = fw.get('per_port_whitelist', {})
    new_ppw = {}
    for k, lst in ppw.items():
        ck = canonicalize_spec(k)
        uniq = []
        for cidr in lst or []:
            if cidr not in uniq:
                uniq.append(cidr)
        new_ppw.setdefault(ck, uniq)
    fw['open_ports'] = sorted_specs(list(open_set))
    fw['blocked_ports'] = sorted_specs(list(blocked_set))
    fw['per_port_whitelist'] = new_ppw

def sorted_specs(lst):
    def _key(s):
        p, pr = parse_portdef(s)
        return (pr, p)
    return sorted(set(lst), key=_key)

def is_ipv4_cidr(s: str) -> bool:
    try:
        return ipaddress.ip_network(s, strict=False).version == 4
    except Exception:
        return False

def is_ipv6_cidr(s: str) -> bool:
    try:
        return ipaddress.ip_network(s, strict=False).version == 6
    except Exception:
        return False

def split_cidrs_by_family(cidrs):
    v4, v6 = [], []
    for c in cidrs or []:
        if is_ipv4_cidr(c): v4.append(c)
        elif is_ipv6_cidr(c): v6.append(c)
    return v4, v6

def add_per_port_whitelist(cfg: dict, spec: str, cidr: str):
    spec = canonicalize_spec(spec)
    d = cfg['firewall'].setdefault('per_port_whitelist', {})
    d.setdefault(spec, [])
    if cidr not in d[spec]:
        d[spec].append(cidr)
    ensure_open_port(cfg, spec)

def ensure_open_port(cfg: dict, spec: str):
    spec = canonicalize_spec(spec)
    fw = cfg['firewall']
    lst = fw.setdefault('open_ports', [])
    if spec not in lst: lst.append(spec)
    bl = fw.setdefault('blocked_ports', [])
    if spec in bl: bl.remove(spec)

def add_blocked_port(cfg: dict, spec: str):
    spec = canonicalize_spec(spec)
    fw = cfg['firewall']
    lst = fw.setdefault('blocked_ports', [])
    if spec not in lst: lst.append(spec)
    op = fw.setdefault('open_ports', [])
    if spec in op: op.remove(spec)

    ppw = fw.setdefault('per_port_whitelist', {})
    if spec in ppw: del ppw[spec]

def remove_open_port(cfg: dict, spec: str):
    spec = canonicalize_spec(spec)
    lst = cfg['firewall'].setdefault('open_ports', [])
    if spec in lst: lst.remove(spec)

def remove_blocked_port(cfg: dict, spec: str):
    spec = canonicalize_spec(spec)
    lst = cfg['firewall'].setdefault('blocked_ports', [])
    if spec in lst: lst.remove(spec)

def remove_from_list(lst, item):
    if item in lst: lst.remove(item)

def timed_input(timeout_s: int):
    import threading
    print("Eingabe: ", end="", flush=True)
    box = {"data": None}
    def _reader():
        try:
            box["data"] = sys.stdin.buffer.readline()
        except Exception:
            box["data"] = b""
    t = threading.Thread(target=_reader, daemon=True)
    t.start(); t.join(timeout_s)
    if box["data"] is None: return None
    return _decode_bytes(box["data"])

def build_firewall(cfg: dict, family: str):
    normalize_config(cfg)
    v4, v6 = iptables_cmds()
    ipv6 = cfg['firewall'].get('ipv6', True)

    tmp_v4 = Path('/tmp/secwizard.rules.v4')
    tmp_v6 = Path('/tmp/secwizard.rules.v6')
    tmp_v4.write_text(run('iptables-save').stdout)
    if ipv6:
        tmp_v6.write_text(run('ip6tables-save').stdout)

    for bin_ in (v4, v6) if ipv6 else (v4,):
        run(f"{bin_} -N SECWIZARD-INPUT", check=False)

        for _ in range(20):
            r = run(f"{bin_} -D INPUT -j SECWIZARD-INPUT", check=False)
            if r.returncode != 0:
                break
        run(f"{bin_} -I INPUT 1 -j SECWIZARD-INPUT", check=False)
        run(f"{bin_} -F SECWIZARD-INPUT", check=False)

    def add_append(bin_, rule: str):
        run(f"{bin_} -A SECWIZARD-INPUT {rule}")
    def add_insert(bin_, rule: str):
        run(f"{bin_} -I SECWIZARD-INPUT 1 {rule}")

    ssh_port = int(cfg['firewall'].get('ssh_port', 22))
    allow_est = cfg['firewall'].get('allow_established', True)
    allow_lo = cfg['firewall'].get('allow_loopback', True)
    allow_icmp = cfg['firewall'].get('allow_icmp', True)

    if allow_est:
        add_append(v4, "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
        if ipv6: add_append(v6, "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    if allow_lo:
        add_append(v4, "-i lo -j ACCEPT")
        if ipv6: add_append(v6, "-i lo -j ACCEPT")
    if allow_icmp:
        add_append(v4, "-p icmp -j ACCEPT")
        if ipv6: add_append(v6, "-p ipv6-icmp -j ACCEPT")

    global_wl = cfg['firewall'].get('global_whitelist', [])
    wl4, wl6 = split_cidrs_by_family(global_wl)
    for cidr in wl4:
        add_insert(v4, f"-s {shlex.quote(cidr)} -j ACCEPT")
    if ipv6:
        for cidr in wl6:
            add_insert(v6, f"-s {shlex.quote(cidr)} -j ACCEPT")

    per_port = cfg['firewall'].get('per_port_whitelist', {})
    for spec, srcs in per_port.items():
        p, proto = parse_portdef(spec)
        src4, src6 = split_cidrs_by_family(srcs)
        for cidr in src4:
            add_insert(v4, f"-p {proto} --dport {p} -s {shlex.quote(cidr)} -j ACCEPT")
        if ipv6:
            for cidr in src6:
                add_insert(v6, f"-p {proto} --dport {p} -s {shlex.quote(cidr)} -j ACCEPT")

    key_ssh = f"{ssh_port}/tcp"
    ssh_sources = per_port.get(key_ssh, []) or global_wl
    if ssh_sources:
        src4, src6 = split_cidrs_by_family(ssh_sources)
        for cidr in src4:
            add_insert(v4, f"-p tcp --dport {ssh_port} -s {shlex.quote(cidr)} -j ACCEPT")
        if ipv6:
            for cidr in src6:
                add_insert(v6, f"-p tcp --dport {ssh_port} -s {shlex.quote(cidr)} -j ACCEPT")
    else:
        add_append(v4, f"-p tcp --dport {ssh_port} -j ACCEPT")
        if ipv6:
            add_append(v6, f"-p tcp --dport {ssh_port} -j ACCEPT")

    for spec in sorted_specs(cfg['firewall'].get('open_ports', [])):
        if spec == key_ssh: continue
        p, proto = parse_portdef(spec)
        sources = per_port.get(spec, []) or global_wl
        if sources:
            s4, s6 = split_cidrs_by_family(sources)
            for cidr in s4:
                add_append(v4, f"-p {proto} --dport {p} -s {shlex.quote(cidr)} -j ACCEPT")
            if ipv6:
                for cidr in s6:
                    add_append(v6, f"-p {proto} --dport {p} -s {shlex.quote(cidr)} -j ACCEPT")
        else:
            add_append(v4, f"-p {proto} --dport {p} -j ACCEPT")
            if ipv6:
                add_append(v6, f"-p {proto} --dport {p} -j ACCEPT")

    for spec in sorted_specs(cfg['firewall'].get('blocked_ports', [])):
        p, proto = parse_portdef(spec)
        add_append(v4, f"-p {proto} --dport {p} -j DROP")
        if ipv6:
            add_append(v6, f"-p {proto} --dport {p} -j DROP")

    default_policy = cfg['firewall'].get('default_input_policy', 'DROP').upper()
    if default_policy in ('DROP', 'ACCEPT'):
        run(f"{v4} -P INPUT {default_policy}")
        if ipv6:
            run(f"{v6} -P INPUT {default_policy}")

    if cfg['firewall'].get('docker_aware', True) and docker_installed():
        ensure_docker_user_chain(v4, v6)
        run(f"{v4} -F DOCKER-USER", check=False)
        if ipv6:
            run(f"{v6} -F DOCKER-USER", check=False)
        if cfg['firewall'].get('allow_host_hairpin', True):
            run(f"{v4} -I DOCKER-USER 1 -i lo -j ACCEPT", check=False)
            run(f"{v4} -I DOCKER-USER 1 -s 127.0.0.0/8 -j ACCEPT", check=False)
            if ipv6:
                run(f"{v6} -I DOCKER-USER 1 -s ::1/128 -j ACCEPT", check=False)
        run(f"{v4} -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", check=False)
        if ipv6:
            run(f"{v6} -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", check=False)
        for cidr in wl4:
            run(f"{v4} -I DOCKER-USER 1 -s {shlex.quote(cidr)} -j ACCEPT", check=False)
        if ipv6:
            for cidr in wl6:
                run(f"{v6} -I DOCKER-USER 1 -s {shlex.quote(cidr)} -j ACCEPT", check=False)
        for spec, srcs in per_port.items():
            p, proto = parse_portdef(spec)
            s4, s6 = split_cidrs_by_family(srcs)
            for cidr in s4:
                run(f"{v4} -I DOCKER-USER 1 -p {proto} --dport {p} -s {shlex.quote(cidr)} -j ACCEPT", check=False)
            if ipv6:
                for cidr in s6:
                    run(f"{v6} -I DOCKER-USER 1 -p {proto} --dport {p} -s {shlex.quote(cidr)} -j ACCEPT", check=False)
            run(f"{v4} -A DOCKER-USER -p {proto} --dport {p} -j DROP", check=False)
            if ipv6:
                run(f"{v6} -A DOCKER-USER -p {proto} --dport {p} -j DROP", check=False)
        for spec in sorted_specs(cfg['firewall'].get('blocked_ports', [])):
            p, proto = parse_portdef(spec)
            run(f"{v4} -A DOCKER-USER -p {proto} --dport {p} -j DROP", check=False)
            if ipv6:
                run(f"{v6} -A DOCKER-USER -p {proto} --dport {p} -j DROP", check=False)
        run(f"{v4} -A DOCKER-USER -j RETURN", check=False)
        if ipv6:
            run(f"{v6} -A DOCKER-USER -j RETURN", check=False)
    elif cfg['firewall'].get('docker_aware', True) and not docker_installed():
        print("[INFO] Docker nicht installiert – DOCKER-USER wird nicht angetastet.")

    iptables_save_persist(family)
    seconds = int(cfg['firewall'].get('rescue_seconds', 90))
    print(f"\n[SAFEGUARD] Firewall-Regeln angewandt. Bestätige innerhalb von {seconds} Sekunden mit 'OK' und ENTER, sonst Rollback.")
    sys.stdout.flush()
    confirmed = timed_input(seconds)
    if (confirmed or '').strip().upper() == 'OK':
        print("[OK] Bestätigt. Regeln bleiben aktiv.")
    else:
        print("[ROLLBACK] Keine Bestätigung - setze vorherige Regeln zurück.")
        if tmp_v4.exists():
            run_sh(f"iptables-restore < {shlex.quote(str(tmp_v4))}")
        if ipv6 and tmp_v6.exists():
            run_sh(f"ip6tables-restore < {shlex.quote(str(tmp_v6))}")
        iptables_save_persist(family)
        print("[OK] Vorherige Regeln wiederhergestellt.")

def uid_from_name(name: str) -> int:
    return int(run(f"id -u {shlex.quote(name)}").stdout.strip())

def gid_from_name(name: str) -> int:
    return int(run(f"id -g {shlex.quote(name)}").stdout.strip())

def set_sshd_option(content: str, key: str, value: str) -> str:
    pattern = re.compile(rf'^\s*#?\s*{re.escape(key)}\s+\S.*$',
                         re.IGNORECASE | re.MULTILINE)
    new_line = f"{key} {value}"
    if pattern.search(content):
        return pattern.sub(new_line, content, count=1)
    if not content.endswith('\n'):
        content += '\n'
    return content + new_line + '\n'

def enable_google_authenticator_pam(family: str):
    if family == 'rhel':
        run("dnf -y install epel-release", check=False)
        run("dnf -y install google-authenticator qrencode", check=False)
    elif family == 'debian':
        run("apt-get update", check=False)
        run("apt-get -y install libpam-google-authenticator qrencode", check=False)
    pam = Path('/etc/pam.d/sshd')
    if not pam.exists():
        print("[WARN] /etc/pam.d/sshd nicht vorhanden – Google Authenticator nicht eingerichtet.")
        return
    backup_file(pam)
    txt = pam.read_text()
    if 'pam_google_authenticator.so' in txt:
        return
    if not txt.endswith('\n'):
        txt += '\n'
    txt += "\n# secwizard: TOTP via Google Authenticator (nullok = neue User dürfen ohne)\n"
    txt += "auth required pam_google_authenticator.so nullok\n"
    pam.write_text(txt)

def write_sshd_settings(settings: dict, sshd_main: Path):
    sshd_d = Path('/etc/ssh/sshd_config.d')
    main_text = sshd_main.read_text(encoding='utf-8') if sshd_main.exists() else ''
    has_include = bool(re.search(r'^\s*Include\s+/etc/ssh/sshd_config\.d/', main_text, re.MULTILINE))

    if sshd_d.exists() and has_include:
        target = sshd_d / '00-secwizard.conf'
        backup_file(target)
        body = "# Managed by SecWizard – diese Datei wird automatisch überschrieben.\n"
        for k, v in settings.items():
            body += f"{k} {v}\n"
        target.write_text(body)
        os.chmod(target, 0o644)
        print(f"[OK] SSH-Settings geschrieben: {target}")
    else:

        backup_file(sshd_main)
        conf = main_text
        for k, v in settings.items():
            conf = set_sshd_option(conf, k, v)
        sshd_main.write_text(conf, encoding='utf-8')
        print(f"[OK] SSH-Settings im Hauptfile aktualisiert: {sshd_main}")

def configure_ssh(cfg: dict, family: str):
    print("\n[SSH] Konfiguration starten…")
    sshd_config = Path('/etc/ssh/sshd_config')

    if ask_yn("Neuen Admin-Account für SSH-Key-Login anlegen? (empfohlen)"):
        cfg['ssh']['create_admin'] = True
        while True:
            user = read_line("Benutzername (z.B. admin): ").strip()
            if user:
                cfg['ssh']['admin_user'] = user
                break
        group = 'wheel' if family == 'rhel' else 'sudo'
        res = run(f"id -u {shlex.quote(user)}", check=False)
        if res.returncode != 0:
            run(f"useradd -m -G {group} {shlex.quote(user)}", check=False)
        else:
            run(f"usermod -aG {group} {shlex.quote(user)}", check=False)
        print("Füge mindestens einen SSH Public Key ein (Zeile). Leere Zeile beendet.")
        keys = []
        while True:
            k = read_line("Public Key: ")
            if not k.strip(): break
            keys.append(k.strip())
        if keys:
            cfg['ssh']['admin_keys'] = keys
            auth_dir = Path(f"/home/{user}/.ssh")
            auth_dir.mkdir(parents=True, exist_ok=True)
            auth = auth_dir / 'authorized_keys'
            with open(auth, 'w') as f:
                for k in keys: f.write(k + "\n")
            os.chown(auth_dir, uid_from_name(user), gid_from_name(user))
            os.chmod(auth_dir, 0o700)
            os.chown(auth, uid_from_name(user), gid_from_name(user))
            os.chmod(auth, 0o600)
            print(f"[OK] Keys für {user} geschrieben: {auth}")
        else:
            print("[WARN] Keine Keys angegeben; Benutzer bleibt ohne Keys.")
    else:
        cfg['ssh']['create_admin'] = False

    cfg['ssh']['password_auth'] = ask_yn("PasswordAuthentication in SSH erlauben? (empfohlen: NEIN)")
    cfg['ssh']['disable_root_login'] = ask_yn("Root-Login per SSH deaktivieren? (empfohlen: JA)")
    cfg['ssh']['enable_totp'] = ask_yn("Google Authenticator (TOTP) für SSH aktivieren?")

    settings = {
        'PasswordAuthentication': 'yes' if cfg['ssh']['password_auth'] else 'no',
        'PubkeyAuthentication': 'yes',
        'PermitRootLogin': 'no' if cfg['ssh']['disable_root_login'] else 'prohibit-password',
    }
    if cfg['ssh']['enable_totp']:

        settings['KbdInteractiveAuthentication'] = 'yes'
        settings['ChallengeResponseAuthentication'] = 'yes'
        settings['UsePAM'] = 'yes'
        if ask_yn("AuthenticationMethods auf 'publickey,keyboard-interactive' setzen (echtes 2FA)?"):
            cfg['ssh']['enforce_2fa'] = True
            settings['AuthenticationMethods'] = 'publickey,keyboard-interactive'
        else:
            cfg['ssh']['enforce_2fa'] = False
        enable_google_authenticator_pam(family)

    if (not cfg['ssh']['password_auth']
            and cfg['ssh']['disable_root_login']
            and not cfg['ssh'].get('admin_keys')):
        print("\n[!!! WARNUNG !!!] PasswordAuth ist AUS, Root-Login ist AUS,")
        print("   und es wurden KEINE Public Keys hinterlegt.")
        print("   Bei aktueller Session-Trennung kannst du dich NICHT mehr einloggen!")
        if not ask_yn("Trotzdem fortfahren?"):
            print("[ABBRUCH] SSH-Konfiguration nicht angewandt.")
            return

    write_sshd_settings(settings, sshd_config)

    res = run("sshd -t", check=False)
    if res.returncode != 0:
        print("[ERROR] sshd-Konfigurationsprüfung fehlgeschlagen!")
        print(res.stderr or res.stdout)
        print("[INFO] Backup wiederherstellen mit:")
        print(f"       cp {BACKUP_DIR}/sshd_config.<TIMESTAMP>.bak /etc/ssh/sshd_config")
        return

    restart_sshd()
    print("[OK] sshd neu gestartet.")

def configure_updates(cfg: dict, family: str):
    print("\n[UPDATES] Wöchentliche Updates & Kernel-Reboot konfigurieren…")
    weekday = cfg['updates'].get('weekday', 'Mon')
    upd_h = int(cfg['updates'].get('update_hour', 4))
    reb_h = int(cfg['updates'].get('reboot_hour', 5))
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    rhel_update_cmd = (
        "dnf -y upgrade; "
        "LATEST=$(rpm -q kernel --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}\\n' "
        "  | sort -V | tail -1); "
        "RUNNING=$(uname -r); "
        "if [ \"$LATEST\" != \"$RUNNING\" ]; then "
        "  touch /var/lib/secwizard/kernel-updated; "
        "fi"
    )

    debian_update_cmd = (
        "apt-get update; unattended-upgrade -v; "
        "if [ -f /var/run/reboot-required ]; then "
        "  touch /var/lib/secwizard/kernel-updated; "
        "fi"
    )

    if family == 'rhel':
        run("dnf -y install dnf-automatic", check=False)
        update_exec = rhel_update_cmd
    elif family == 'debian':
        run("apt-get update", check=False)
        run("DEBIAN_FRONTEND=noninteractive apt-get -y install unattended-upgrades", check=False)
        update_exec = debian_update_cmd
    else:
        print("[WARN] Unbekannte OS-Familie - Updates/Reboot nicht automatisiert konfiguriert.")
        return

    service = "/etc/systemd/system/secwizard-weekly-update.service"
    timer = "/etc/systemd/system/secwizard-weekly-update.timer"
    with open(service, 'w') as f:
        f.write(f"""[Unit]
Description=SecWizard Weekly Update

[Service]
Type=oneshot
ExecStart=/usr/bin/bash -lc {shlex.quote(update_exec)}
""")
    with open(timer, 'w') as f:
        f.write(f"""[Unit]
Description=Run SecWizard Weekly Update

[Timer]
OnCalendar={weekday} {upd_h:02d}:00
Persistent=true

[Install]
WantedBy=timers.target
""")
    run("systemctl daemon-reload", check=False)
    run("systemctl enable --now secwizard-weekly-update.timer", check=False)

    service2 = "/etc/systemd/system/secwizard-kernel-reboot.service"
    timer2 = "/etc/systemd/system/secwizard-kernel-reboot.timer"
    with open(service2, 'w') as f:
        f.write("""[Unit]
Description=SecWizard Conditional Kernel Reboot

[Service]
Type=oneshot
ExecStart=/usr/bin/bash -lc 'if [ -f /var/lib/secwizard/kernel-updated ]; then rm -f /var/lib/secwizard/kernel-updated; systemctl reboot; fi'
""")
    with open(timer2, 'w') as f:
        f.write(f"""[Unit]
Description=Run SecWizard Conditional Kernel Reboot

[Timer]
OnCalendar={weekday} {reb_h:02d}:00
Persistent=true

[Install]
WantedBy=timers.target
""")
    run("systemctl daemon-reload", check=False)
    run("systemctl enable --now secwizard-kernel-reboot.timer", check=False)
    print("[OK] Update- und Reboot-Timer aktiviert.")

def generate_selfsigned(cert_cn: str, days: int = 3650):
    PKI_DIR.mkdir(parents=True, exist_ok=True)
    key = PKI_DIR / 'server.key'
    crt = PKI_DIR / 'server.crt'
    cmd = (
        f"openssl req -x509 -newkey rsa:4096 -sha256 -days {days} "
        f"-nodes -keyout {shlex.quote(str(key))} -out {shlex.quote(str(crt))} "
        f"-subj /CN={shlex.quote(cert_cn)}"
    )
    run_sh(cmd, check=False)
    if key.exists():
        os.chmod(key, 0o600)
    print(f"[OK] Selbstsigniertes Zertifikat erstellt: {crt} (Key: {key})")

def write_example_compose(which: str):
    EXAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    if which == 'nginx':
        content = f"""
services:
  waf:
    image: owasp/modsecurity:nginx
    ports:
      - "443:443"
    volumes:
      - {PKI_DIR}:/etc/nginx/pki:ro
      - /opt/owasp-crs:/etc/nginx/owasp-crs:ro
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    environment:
      - MODSECURITY=true
      - OWASP_CRS=true
    restart: unless-stopped
"""
        (EXAMPLES_DIR / 'nginx-modsec-compose.yml').write_text(content)
        (EXAMPLES_DIR / 'README-nginx.txt').write_text(
            "OWASP CRS Repo nach /opt/owasp-crs klonen. nginx.conf anpassen und Backend-Upstreams setzen.\n"
        )
    elif which == 'apache':
        content = f"""
services:
  waf:
    image: owasp/modsecurity-crs:apache
    ports:
      - "443:443"
    volumes:
      - {PKI_DIR}:/usr/local/apache2/conf/pki:ro
      - /opt/owasp-crs:/etc/httpd/owasp-crs:ro
      - ./httpd.conf:/usr/local/apache2/conf/httpd.conf:ro
    restart: unless-stopped
"""
        (EXAMPLES_DIR / 'apache-modsec-compose.yml').write_text(content)
        (EXAMPLES_DIR / 'README-apache.txt').write_text(
            "OWASP CRS Repo nach /opt/owasp-crs klonen. httpd.conf anpassen und Backend ProxyPass setzen.\n"
        )
    elif which == 'haproxy':
        content = f"""
services:
  haproxy:
    image: haproxy:alpine
    ports:
      - "443:443"
    volumes:
      - {PKI_DIR}:/etc/haproxy/pki:ro
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    restart: unless-stopped
"""
        (EXAMPLES_DIR / 'haproxy-compose.yml').write_text(content)
        (EXAMPLES_DIR / 'README-haproxy.txt').write_text(
            "Für WAF-Unterstützung empfohlen: vorgeschalteten NGINX+ModSecurity nutzen oder SPOE/Sidecar evaluieren.\n"
        )

def configure_web(cfg: dict):
    print("\n[WEB] Web/SSL/WAF Konfiguration…")
    is_web = ask_yn("Wird dieser Server ein Webserver/Reverse-Proxy?")
    cfg['web']['is_webserver'] = is_web
    if not is_web:
        return
    if ask_yn("Soll ein 10-Jahre selbstsigniertes Zertifikat erzeugt werden (intern)?"):
        cfg['web']['selfsigned_cert'] = True
        cn = read_line(f"Common Name (CN) für Zertifikat [{socket.gethostname()}]: ").strip() or socket.gethostname()
        cfg['web']['cert_cn'] = cn
        generate_selfsigned(cert_cn=cn, days=cfg['web'].get('cert_days', 3650))
    else:
        cfg['web']['selfsigned_cert'] = False

    role_under = ask_yn("Ist dies ein Unter-Webserver (hinter einem externen LoadBalancer)?")
    role = 'underwebserver' if role_under else 'loadbalancer'
    cfg['firewall']['web_role'] = role
    if role == 'underwebserver':
        print("Dieser Host soll 443 nur vom LoadBalancer annehmen.")
        while True:
            lb = read_line("IP oder CIDR des LoadBalancers: ").strip()
            if lb:
                cfg['firewall']['lb_ip'] = lb
                add_per_port_whitelist(cfg, '443/tcp', lb)
                if ask_yn("Port 80 (HTTP) blockieren?"):
                    add_blocked_port(cfg, '80/tcp')
                break
    else:
        print("LoadBalancer-Rolle: 443 wird grundsätzlich offen sein (Public).")
        ensure_open_port(cfg, '443/tcp')

        if ask_yn("Port 80 ebenfalls öffnen (z.B. für ACME/HTTP→HTTPS)?"):
            ensure_open_port(cfg, '80/tcp')
        elif ask_yn("Port 80 explizit blockieren?"):
            add_blocked_port(cfg, '80/tcp')

    choice = ask_choice("Welcher Proxy/Webserver soll verwendet werden?",
                        ["nginx", "apache", "haproxy", "keiner"])
    if choice != 'keiner':
        write_example_compose(choice)
        print(f"[OK] Beispiel-Compose für {choice} mit Hinweisen unter {EXAMPLES_DIR} abgelegt.")

def configure_fail2ban(cfg: dict, family: str):
    if not ask_yn("Fail2ban installieren & aktivieren für sshd?"):
        cfg['fail2ban']['enable'] = False
        return
    cfg['fail2ban']['enable'] = True
    if family == 'rhel':
        run("dnf -y install epel-release", check=False)
        run("dnf -y install fail2ban", check=False)
        Path('/etc/fail2ban').mkdir(parents=True, exist_ok=True)
        Path('/etc/fail2ban/jail.local').write_text("""
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port    = ssh
filter  = sshd
backend = systemd
""")
        run("systemctl enable --now fail2ban", check=False)
    elif family == 'debian':
        run("apt-get update", check=False)
        run("apt-get -y install fail2ban", check=False)
        Path('/etc/fail2ban').mkdir(parents=True, exist_ok=True)
        Path('/etc/fail2ban/jail.local').write_text("""
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port    = ssh
filter  = sshd
backend = systemd
""")
        run("systemctl enable --now fail2ban", check=False)
    else:
        print("[WARN] Unbekannte OS-Familie - bitte Fail2ban manuell installieren.")

def configure_selinux(cfg: dict, family: str):
    if family != 'rhel':
        print("[INFO] SELinux-Verwaltung nur relevant auf RHEL/Alma.")
        return
    if not ask_yn("SELinux verwalten (Empfohlen: Enforcing beibehalten)?"):
        cfg['selinux']['manage'] = False
        return
    cfg['selinux']['manage'] = True

    cur = run("getenforce", check=False)
    cur_state = (cur.stdout or '').strip().lower() if cur.returncode == 0 else 'unknown'
    print(f"[INFO] Aktueller SELinux-Status: {cur_state}")

    enforcing = ask_yn("SELinux auf 'enforcing' setzen?")
    cfg['selinux']['enforcing'] = enforcing
    target = 'enforcing' if enforcing else 'permissive'

    config = Path('/etc/selinux/config')
    if config.exists():
        backup_file(config)
        txt = config.read_text()

        new_txt, n = re.subn(r'^\s*SELINUX\s*=\s*\w+', f'SELINUX={target}',
                             txt, flags=re.MULTILINE)
        if n == 0:
            new_txt = txt + (f"\nSELINUX={target}\n" if not txt.endswith('\n')
                             else f"SELINUX={target}\n")
        config.write_text(new_txt)
        print(f"[OK] /etc/selinux/config angepasst: SELINUX={target}")

    if cur_state == 'disabled' and target in ('enforcing', 'permissive'):
        print("\n[!!! ACHTUNG !!!] SELinux war deaktiviert. Das Dateisystem hat keine")
        print("    aktuellen SELinux-Kontexte. Beim nächsten Boot in 'enforcing' werden")
        print("    sehr wahrscheinlich Services scheitern.")
        print("    Lege /.autorelabel an und plane einen Reboot ein.")
        Path('/.autorelabel').touch()
        print("[OK] /.autorelabel angelegt – beim nächsten Reboot wird relabelt.")
        print("     >> Bitte zeitnah `reboot` durchführen! <<")
    elif target == 'enforcing' and cur_state == 'permissive':
        run("setenforce 1", check=False)
        print("[OK] setenforce 1 ausgeführt.")
    elif target == 'permissive' and cur_state == 'enforcing':
        run("setenforce 0", check=False)
        print("[OK] setenforce 0 ausgeführt.")

def ask_yn(prompt: str) -> bool:
    while True:
        ans = read_line(f"{prompt} [y/n]: ").strip().lower()
        if ans in ('y', 'yes', 'j', 'ja'): return True
        if ans in ('n', 'no', 'nein'): return False

def ask_choice(prompt: str, options: list) -> str:
    print(prompt)
    for i, opt in enumerate(options, start=1):
        print(f"  {i}) {opt}")
    while True:
        s = read_line("Auswahl: ").strip()
        if s.isdigit() and 1 <= int(s) <= len(options):
            return options[int(s) - 1]

def iptables_live_state() -> dict:
    state = {
        'available': False,
        'secwizard_active': False,
        'rules_in_chain_v4': 0,
        'rules_in_chain_v6': 0,
        'input_policy_v4': 'unknown',
        'input_policy_v6': 'unknown',
        'open_ports_v4': [],
    }
    if not shutil_which('iptables'):
        return state
    state['available'] = True

    res = run("iptables -S SECWIZARD-INPUT", check=False)
    if res.returncode == 0:
        state['secwizard_active'] = True

        rules = [l for l in (res.stdout or '').splitlines()
                 if l.strip() and not l.startswith('-N ')]
        state['rules_in_chain_v4'] = len(rules)

        opens = []
        for ln in rules:
            m_proto = re.search(r'-p\s+(tcp|udp)\b', ln)
            m_dport = re.search(r'--dport\s+(\d+)', ln)
            if m_proto and m_dport and ' -j ACCEPT' in ln:
                opens.append(f"{m_dport.group(1)}/{m_proto.group(1)}")
        state['open_ports_v4'] = sorted(set(opens))

    if shutil_which('ip6tables'):
        res6 = run("ip6tables -S SECWIZARD-INPUT", check=False)
        if res6.returncode == 0:
            rules6 = [l for l in (res6.stdout or '').splitlines()
                      if l.strip() and not l.startswith('-N ')]
            state['rules_in_chain_v6'] = len(rules6)

    res = run("iptables -S INPUT", check=False)
    if res.returncode == 0:
        for ln in (res.stdout or '').splitlines():
            if ln.startswith('-P INPUT'):
                state['input_policy_v4'] = ln.split()[-1]
                break
    if shutil_which('ip6tables'):
        res = run("ip6tables -S INPUT", check=False)
        if res.returncode == 0:
            for ln in (res.stdout or '').splitlines():
                if ln.startswith('-P INPUT'):
                    state['input_policy_v6'] = ln.split()[-1]
                    break
    return state

def fw_config_matches_live(cfg: dict) -> bool:
    live = iptables_live_state()
    if not live['available'] or not live['secwizard_active']:
        return False
    fw = cfg.get('firewall', {})
    cfg_pol = fw.get('default_input_policy', 'DROP').upper()
    if live['input_policy_v4'] != cfg_pol:
        return False

    expected = set()
    expected.add(f"{fw.get('ssh_port', 22)}/tcp")
    for spec in fw.get('open_ports', []):
        expected.add(canonicalize_spec(spec))
    for spec in fw.get('per_port_whitelist', {}).keys():
        expected.add(canonicalize_spec(spec))
    blocked = {canonicalize_spec(s) for s in fw.get('blocked_ports', [])}
    expected -= blocked
    live_ports = set(live['open_ports_v4'])

    return expected.issubset(live_ports)

def print_fw_status(cfg: dict):
    normalize_config(cfg)
    fw = cfg['firewall']
    print("\n--- Firewall-Konfiguration (Sollzustand aus config.json) ---")
    print(f"Default INPUT Policy: {fw.get('default_input_policy', 'DROP').upper()}")
    print(f"IPv6 aktiviert: {'ja' if fw.get('ipv6', True) else 'nein'}")
    print(f"ICMP erlaubt: {'ja' if fw.get('allow_icmp', True) else 'nein'}")
    print(f"SSH-Port: {fw.get('ssh_port', 22)}/tcp")
    print(f"Docker-aware: {'ja' if fw.get('docker_aware', True) else 'nein'} "
          f"(Docker installiert: {'ja' if docker_installed() else 'nein'})")
    print("Open Ports:", ", ".join(sorted_specs(fw.get('open_ports', []))) or "(leer)")
    print("Blocked Ports:", ", ".join(sorted_specs(fw.get('blocked_ports', []))) or "(leer)")
    print("Global Whitelist:", ", ".join(fw.get('global_whitelist', [])) or "(leer)")
    print("Per-Port Whitelist:")
    for k, v in fw.get('per_port_whitelist', {}).items():
        print(f"  {k}: {', '.join(v) or '(leer)'}")

    live = iptables_live_state()
    print("\n--- Live iptables-Status (was aktuell wirklich gilt) ---")
    if not live['available']:
        print("  iptables nicht installiert.")
    else:
        if not live['secwizard_active']:
            print("  ⚠️  SECWIZARD-INPUT Chain existiert NICHT im Kernel.")
            print("     → Die obige Konfig wurde NIE angewandt!")
            print("     → Wähle Menüpunkt 8 ('Regeln anwenden'), damit etwas passiert.")
        else:
            print(f"  SECWIZARD-INPUT aktiv mit {live['rules_in_chain_v4']} IPv4-Regeln "
                  f"({live['rules_in_chain_v6']} IPv6-Regeln)")
            if live['open_ports_v4']:
                print("  ACCEPTed dports (live):", ", ".join(live['open_ports_v4']))
        print(f"  Live INPUT-Policy v4: {live['input_policy_v4']}", end='')
        cfg_pol = fw.get('default_input_policy', 'DROP').upper()
        if live['input_policy_v4'] not in ('unknown', cfg_pol):
            print(f"   ⚠️  weicht von Konfig ({cfg_pol}) ab!")
        else:
            print()
        if fw.get('ipv6', True):
            print(f"  Live INPUT-Policy v6: {live['input_policy_v6']}", end='')
            if live['input_policy_v6'] not in ('unknown', cfg_pol):
                print(f"   ⚠️  weicht von Konfig ({cfg_pol}) ab!")
            else:
                print()

        if live['input_policy_v4'] == 'ACCEPT' and live['rules_in_chain_v4'] == 0:
            print("\n  ⚠️  ACHTUNG: INPUT-Policy ist ACCEPT und es gibt keine eigenen Regeln.")
            print("     Effektiv ist deine Maschine WEIT OFFEN, egal was die Konfig sagt.")
    print("------------------------------------------------------------\n")

def manage_firewall_flow(cfg: dict, family: str):
    print("\n[FIREWALL] Verwaltung starten…")

    initial_hash = json.dumps(cfg.get('firewall', {}), sort_keys=True)
    while True:

        live = iptables_live_state()
        current_hash = json.dumps(cfg.get('firewall', {}), sort_keys=True)
        if not live['secwizard_active']:
            status_hint = "  [Status: Regeln NICHT aktiv – noch nie angewandt]"
        elif current_hash != initial_hash:
            status_hint = "  [Status: Konfig geändert – noch nicht angewandt]"
        else:
            status_hint = "  [Status: Regeln aktiv]"
        print(f"""
{status_hint}
1) Port öffnen (hinzufügen/entfernen)
2) Port blockieren (hinzufügen/entfernen)
3) Global-Whitelist bearbeiten (hinzufügen/entfernen)
4) Whitelist pro Port bearbeiten (hinzufügen/entfernen)
5) SSH-Port festlegen
6) IPv6 ein/aus
7) Default INPUT-Policy (ACCEPT/DROP) setzen
8) Regeln anwenden (mit Rescue-Fenster)   <-- erst hier wirken Änderungen
9) Aktuellen Status anzeigen
10) Zurück
""")
        sel = read_line("Auswahl: ").strip()
        if sel == '1':
            while True:
                print("a) Öffnen hinzufügen   b) Öffnen entfernen   d) Auflisten   c) Zurück")
                sub = read_line("Auswahl: ").strip().lower()
                if sub == 'a':
                    raw = read_line("Port(-/proto), z.B. 443/tcp oder 53: ").strip().lower()
                    if not raw: continue
                    spec = ensure_spec_interactive(raw)
                    ensure_open_port(cfg, spec)
                    normalize_config(cfg)
                    print(f"[OK] {spec} zu open_ports hinzugefügt.")
                elif sub == 'b':
                    raw = read_line("Welchen offenen Port entfernen? ").strip().lower()
                    if not raw: continue
                    spec = ensure_spec_interactive(raw)
                    remove_open_port(cfg, spec)
                    normalize_config(cfg)
                    print(f"[OK] {spec} aus open_ports entfernt.")
                elif sub == 'd':
                    lst = sorted_specs(cfg['firewall'].get('open_ports', []))
                    print("\nGeplant offene Ports (Konfig):")
                    if not lst:
                        print("  (leer)")
                    else:
                        for s in lst:
                            print(f"  - {s}")

                    live = iptables_live_state()
                    if live['secwizard_active']:
                        print("Live offene dports laut iptables:")
                        if live['open_ports_v4']:
                            for s in live['open_ports_v4']:
                                print(f"  - {s}")
                        else:
                            print("  (keine ACCEPT-Regeln in SECWIZARD-INPUT mit --dport)")
                    print()
                elif sub == 'c':
                    break
        elif sel == '2':
            while True:
                print("a) Blockierung hinzufügen   b) Blockierung entfernen   d) Auflisten   c) Zurück")
                sub = read_line("Auswahl: ").strip().lower()
                if sub == 'a':
                    raw = read_line("Port(-/proto): ").strip().lower()
                    if not raw: continue
                    spec = ensure_spec_interactive(raw)
                    add_blocked_port(cfg, spec)
                    normalize_config(cfg)
                    print(f"[OK] {spec} zu blocked_ports hinzugefügt.")
                elif sub == 'b':
                    raw = read_line("Welche Blockierung entfernen? ").strip().lower()
                    if not raw: continue
                    spec = ensure_spec_interactive(raw)
                    remove_blocked_port(cfg, spec)
                    normalize_config(cfg)
                    print(f"[OK] {spec} aus blocked_ports entfernt.")
                elif sub == 'd':
                    lst = sorted_specs(cfg['firewall'].get('blocked_ports', []))
                    print("\nGeplant blockierte Ports (Konfig):")
                    if not lst:
                        print("  (leer)")
                    else:
                        for s in lst:
                            print(f"  - {s}")
                    print()
                elif sub == 'c':
                    break
        elif sel == '3':
            while True:
                print("a) Hinzufügen  b) Entfernen  d) Auflisten  c) Zurück")
                op = read_line("Auswahl: ").strip().lower()
                if op == 'a':
                    cidr = read_line("CIDR hinzufügen (z.B. 203.0.113.0/24): ").strip()
                    if not cidr: continue
                    if not (is_ipv4_cidr(cidr) or is_ipv6_cidr(cidr)):
                        print("[WARN] Kein gültiger CIDR – ignoriert.")
                    else:
                        lst = cfg['firewall'].setdefault('global_whitelist', [])
                        if cidr not in lst:
                            lst.append(cidr)
                            print(f"[OK] {cidr} zur global_whitelist hinzugefügt.")
                        else:
                            print(f"[INFO] {cidr} steht bereits drin.")
                elif op == 'b':
                    cidr = read_line("CIDR entfernen: ").strip()
                    if not cidr: continue
                    lst = cfg['firewall'].setdefault('global_whitelist', [])
                    if cidr in lst:
                        lst.remove(cidr)
                        print(f"[OK] {cidr} aus global_whitelist entfernt.")
                    else:
                        print(f"[INFO] {cidr} war nicht in der Liste.")
                elif op == 'd':
                    lst = cfg['firewall'].get('global_whitelist', [])
                    print("\nGlobal Whitelist (Konfig):")
                    if not lst:
                        print("  (leer)")
                    else:
                        for c in lst:
                            print(f"  - {c}")
                    print()
                elif op == 'c':
                    break
            normalize_config(cfg)
        elif sel == '4':
            raw_spec = read_line("Port(-/proto): ").strip().lower()
            if not raw_spec:
                continue
            spec = ensure_spec_interactive(raw_spec)
            d = cfg['firewall'].setdefault('per_port_whitelist', {})
            d.setdefault(spec, [])
            ensure_open_port(cfg, spec)
            while True:
                print(f"\n[Per-Port Whitelist für {spec}]")
                print("a) CIDR hinzufügen  b) CIDR entfernen  d) Auflisten  c) Zurück")
                op = read_line("Auswahl: ").strip().lower()
                if op == 'a':
                    cidr = read_line("CIDR: ").strip()
                    if not cidr: continue
                    if not (is_ipv4_cidr(cidr) or is_ipv6_cidr(cidr)):
                        print("[WARN] Kein gültiger CIDR – ignoriert.")
                    elif cidr in d[spec]:
                        print(f"[INFO] {cidr} steht bereits in der Whitelist für {spec}.")
                    else:
                        d[spec].append(cidr)
                        print(f"[OK] {cidr} zur Whitelist von {spec} hinzugefügt.")
                elif op == 'b':
                    cidr = read_line("CIDR: ").strip()
                    if not cidr: continue
                    if cidr in d[spec]:
                        d[spec].remove(cidr)
                        print(f"[OK] {cidr} aus Whitelist von {spec} entfernt.")
                    else:
                        print(f"[INFO] {cidr} war nicht in der Whitelist von {spec}.")
                elif op == 'd':
                    print(f"\nWhitelist für {spec} (Konfig):")
                    if not d[spec]:
                        print("  (leer)")
                    else:
                        for c in d[spec]:
                            print(f"  - {c}")
                    print()
                elif op == 'c':
                    break
            normalize_config(cfg)
        elif sel == '5':
            p = read_line("SSH-Port (Default 22): ").strip()
            if p.isdigit():
                cfg['firewall']['ssh_port'] = int(p)
                ensure_open_port(cfg, f"{p}/tcp")
                normalize_config(cfg); print_fw_status(cfg)
        elif sel == '6':
            cfg['firewall']['ipv6'] = ask_yn("IPv6-Regeln aktivieren?")
            print_fw_status(cfg)
        elif sel == '7':
            dp = ask_choice("Default INPUT Policy wählen:", ["DROP", "ACCEPT"])
            cfg['firewall']['default_input_policy'] = dp
            print_fw_status(cfg)
        elif sel == '8':
            save_config(cfg)
            build_firewall(cfg, family)
        elif sel == '9':
            print_fw_status(cfg)
        elif sel == '10':

            final_hash = json.dumps(cfg.get('firewall', {}), sort_keys=True)
            live_now = iptables_live_state()
            if final_hash != initial_hash:
                print("\n[!] Die Firewall-Konfig wurde geändert, ist aber noch NICHT")
                print("    in iptables geschrieben.")
                if ask_yn("Jetzt anwenden (mit Rescue-Fenster)?"):
                    save_config(cfg)
                    build_firewall(cfg, family)
            elif not live_now['secwizard_active']:
                print("\n[!] Es existieren noch GAR KEINE eigenen Firewall-Regeln im Kernel.")
                print("    Die gespeicherte Konfig ist also reine Theorie.")
                if ask_yn("Konfig jetzt in iptables schreiben (mit Rescue-Fenster)?"):
                    save_config(cfg)
                    build_firewall(cfg, family)
            break

def ask_special_ports(cfg: dict):
    print("\n[OPTIONAL] Zusätzliche besondere Ports definieren (offen/Whitelist).")
    while ask_yn("Möchtest du einen weiteren Port konfigurieren?"):
        raw = read_line("Port(-/proto), z.B. 8080/tcp oder 53: ").strip().lower()
        spec = ensure_spec_interactive(raw)
        ensure_open_port(cfg, spec)
        if ask_yn("Sollen nur bestimmte IPs/Netze auf diesen Port dürfen?"):
            while True:
                cidr = read_line("CIDR (leer zum Beenden): ").strip()
                if not cidr: break
                if not (is_ipv4_cidr(cidr) or is_ipv6_cidr(cidr)):
                    print("[WARN] Kein gültiger CIDR – ignoriert."); continue
                add_per_port_whitelist(cfg, spec, cidr)
        normalize_config(cfg)

def main_menu():
    ensure_root()
    cfg = load_config()
    family, pretty, version_id, distro_id = detect_os()
    normalize_config(cfg)
    print(f"OS erkannt: {pretty} (Familie: {family}, Version: {version_id or '?'})")

    ensure_base_packages(family, version_id, distro_id)
    setup_iptables_backend(family)

    _live = iptables_live_state()
    if _live['available']:
        if not _live['secwizard_active']:
            print("\n[ACHTUNG] SECWIZARD-INPUT ist NICHT aktiv. Die gespeicherte Konfig")
            print("          unter /etc/secwizard/config.json wirkt sich erst aus, wenn")
            print("          du im Firewall-Menü Punkt 8 ('Regeln anwenden') aufrufst")
            print("          oder den ganzen Wizard (Punkt 1) durchläufst.")
        if (_live['input_policy_v4'] == 'ACCEPT'
                and _live['rules_in_chain_v4'] == 0):
            print("[ACHTUNG] INPUT-Policy ist aktuell ACCEPT und es gibt keine eigenen")
            print("          Regeln – effektiv ist die Maschine WEIT OFFEN!")

    while True:
        print("""
==== SecWizard - Hauptmenü ====
1) Gesamten Wizard durchlaufen
2) Nur Firewall verwalten
3) Nur SSH härten/konfigurieren
4) Nur Updates & Reboot planen
5) Nur Web/TLS/WAF konfigurieren
6) Nur Fail2ban konfigurieren
7) Nur SELinux verwalten
8) Beenden
""")
        sel = read_line("Auswahl: ").strip()
        if sel == '1':
            configure_web(cfg)
            ask_special_ports(cfg)
            configure_ssh(cfg, family)
            configure_fail2ban(cfg, family)
            configure_selinux(cfg, family)
            configure_updates(cfg, family)
            save_config(cfg)
            build_firewall(cfg, family)
        elif sel == '2':
            manage_firewall_flow(cfg, family)
            save_config(cfg)
        elif sel == '3':
            configure_ssh(cfg, family); save_config(cfg)
        elif sel == '4':
            configure_updates(cfg, family); save_config(cfg)
        elif sel == '5':
            configure_web(cfg); save_config(cfg)
        elif sel == '6':
            configure_fail2ban(cfg, family); save_config(cfg)
        elif sel == '7':
            configure_selinux(cfg, family); save_config(cfg)
        elif sel == '8':
            print("Bye."); break
        else:
            print("Ungültige Auswahl.")

if __name__ == '__main__':
    main_menu()