#!/usr/bin/env python3

import os
import re
import sys
from typing import Any, Dict, List, Tuple, Optional

YAML_AVAILABLE = True
try:
    import yaml
except Exception:
    YAML_AVAILABLE = False

RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BLUE = "\033[34m"
DIM = "\033[2m"
RESET = "\033[0m"

SENSITIVE_HOST_PATHS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/usr",
    "/lib",
)
SECRET_KEY_PAT = re.compile(r"(password|passwd|secret|token|apikey|api_key|access_key|private_key)", re.I)
CERT_HINT_PAT = re.compile(r"\.(pem|crt|key)$", re.I)
TLS_SECRET_HINT_PAT = re.compile(r"(tls|cert|certificate|letsencrypt|haproxy|nginx).*", re.I)
DB_PUBLISHED_PORTS = {3306, 5432, 6379, 27017}

def ask_path() -> str:
    print(f"{BLUE}Pfad zu deiner docker-compose oder docker-stack Datei angeben (z. B. /root/snakecloud/docker-stack.yml):{RESET}")
    p = input("> ").strip()
    if not p:
        print(f"{RED}Kein Pfad angegeben.{RESET}")
        sys.exit(2)
    if not os.path.isfile(p):
        print(f"{RED}Datei nicht gefunden:{RESET} {p}")
        sys.exit(2)
    return p

def load_yaml(text: str) -> Optional[Dict[str, Any]]:
    if not YAML_AVAILABLE:
        return None
    try:
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None

def warn(msg: str, service: Optional[str] = None, level: str = "WARN") -> str:
    color = YELLOW if level == "WARN" else RED
    scope = f"[{service}]" if service else "[GLOBAL]"
    return f"{color}{level}{RESET} {scope} {msg}"

def info(msg: str, service: Optional[str] = None) -> str:
    scope = f"[{service}]" if service else "[INFO]"
    return f"{DIM}INFO{RESET} {scope} {msg}"

def iter_services(doc: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    services = doc.get("services") or {}
    if not isinstance(services, dict):
        return []
    return [(name, svc) for name, svc in services.items() if isinstance(svc, dict)]

def get_image_tag(image: str) -> Tuple[str, Optional[str], Optional[str]]:
    digest = None
    if "@sha256:" in image:
        image, digest = image.split("@sha256:", 1)
    tag = None
    if ":" in image:
        name, tag = image.rsplit(":", 1)
    else:
        name = image
    return name, tag, digest

def is_bind_mount(vol: Any) -> Tuple[bool, str, bool]:
    if isinstance(vol, dict):
        if vol.get("type") == "bind" and isinstance(vol.get("source"), str):
            ro = bool(vol.get("read_only") or vol.get("readOnly"))
            return True, vol["source"], ro
        return (False, "", False)
    if isinstance(vol, str) and ":" in vol:
        src = vol.split(":", 1)[0]
        ro = vol.endswith(":ro") or vol.endswith(":ro,Z") or vol.endswith(":ro,z")
        return True, src, ro
    return (False, "", False)

def parse_ports_entry(p: Any) -> List[Tuple[Optional[int], str]]:
    out: List[Tuple[Optional[int], str]] = []
    if isinstance(p, dict):
        pub = p.get("published")
        proto = str(p.get("protocol", "tcp")).lower()
        if isinstance(pub, int):
            out.append((pub, proto))
    elif isinstance(p, str):
        s = p.split("/", 1)[0]
        if ":" in s:
            left = s.split(":")[0]
            try:
                out.append((int(left) if left else None, "tcp"))
            except ValueError:
                out.append((None, "tcp"))
        else:
            try:
                out.append((int(s), "tcp"))
            except ValueError:
                out.append((None, "tcp"))
    return out

def has_cert_hint(svc: Dict[str, Any]) -> bool:
    vols = svc.get("volumes") or []
    for v in vols:
        if isinstance(v, dict):
            src = str(v.get("source", ""))
            tgt = str(v.get("target", ""))
            if CERT_HINT_PAT.search(src) or CERT_HINT_PAT.search(tgt):
                return True
        elif isinstance(v, str):
            parts = v.split(":")
            if any(CERT_HINT_PAT.search(x) for x in parts):
                return True
    secrets = svc.get("secrets") or []
    if isinstance(secrets, list):
        for s in secrets:
            name = s if isinstance(s, str) else str(s.get("source", ""))
            if TLS_SECRET_HINT_PAT.match(name):
                return True
    return False

def run_checks(doc: Dict[str, Any]) -> List[str]:
    findings: List[str] = []
    any_http_published = False
    any_https_published = False

    for svc_name, svc in iter_services(doc):
        image = svc.get("image")
        if image and isinstance(image, str):
            name, tag, digest = get_image_tag(image)
            if digest:
                findings.append(warn(f"Image '{image}' ist per Digest gepinnt – entspricht nicht ':latest' (deine Regel).", svc_name))
            elif tag and tag.lower() != "latest":
                findings.append(warn(f"Image '{image}' nutzt keinen ':latest'-Tag.", svc_name))
            elif not tag:
                findings.append(info(f"Image '{image}' ohne Tag → implizit ':latest'.", svc_name))

        if "user" not in svc:
            findings.append(warn("Kein 'user:' gesetzt – Container läuft vermutlich als root.", svc_name))
        else:
            u = str(svc.get("user"))
            if u in ("0", "root"):
                findings.append(warn(f"'user: {u}' → läuft als root.", svc_name))

        if svc.get("privileged") is True:
            findings.append(warn("privileged: true gesetzt.", svc_name))
        caps = svc.get("cap_add") or []
        if isinstance(caps, list) and any(str(c).upper() in ("ALL", "SYS_ADMIN", "NET_ADMIN") for c in caps):
            findings.append(warn(f"cap_add enthält weitreichende Fähigkeiten: {caps}", svc_name))
        sec = svc.get("security_opt") or []
        if isinstance(sec, list) and any("unconfined" in str(x) for x in sec):
            findings.append(warn(f"security_opt enthält '*unconfined*' → reduzierte Isolation: {sec}", svc_name))

        vols = svc.get("volumes") or []
        if isinstance(vols, list):
            for v in vols:
                is_bind, src, ro = is_bind_mount(v)
                if is_bind:
                    if any(src == p or src.startswith(p + "/") for p in SENSITIVE_HOST_PATHS):
                        if "docker.sock" in src:
                            findings.append(warn(f"Docker-Socket gemountet: {src}", svc_name))
                        elif not ro:
                            findings.append(warn(f"Sensitiver Host-Pfad gemountet ohne read-only: {src}", svc_name))
                        else:
                            findings.append(info(f"Sensitiver Host-Pfad gemountet (read-only): {src}", svc_name))

        if str(svc.get("network_mode", "")).lower() == "host":
            findings.append(warn("network_mode: host verwendet.", svc_name))

        ports = svc.get("ports") or []
        if isinstance(ports, list):
            for p in ports:
                for published, proto in parse_ports_entry(p):
                    if published == 80 and proto == "tcp":
                        any_http_published = True
                    if published == 443 and proto == "tcp":
                        any_https_published = True
                    if isinstance(published, int) and published in DB_PUBLISHED_PORTS:
                        findings.append(warn(f"Datenbank-Port {published} veröffentlicht – TLS/Firewall prüfen.", svc_name))
                if isinstance(p, dict) and str(p.get("mode", "")).lower() == "host":
                    findings.append(warn("Port im Host-Mode veröffentlicht (mode: host).", svc_name))

        if "healthcheck" not in svc and not ("deploy" in svc and "healthcheck" in svc.get("deploy", {})):
            findings.append(warn("Kein Healthcheck definiert.", svc_name))

        deploy = svc.get("deploy") or []
        if isinstance(deploy, dict) and "restart_policy" not in deploy:
            findings.append(warn("Keine 'deploy.restart_policy' gesetzt.", svc_name))

        env = svc.get("environment") or {}
        if isinstance(env, dict):
            for k, v in env.items():
                if SECRET_KEY_PAT.search(str(k)) and isinstance(v, str):
                    if not v.startswith("/run/secrets/"):
                        findings.append(warn(f"'{k}' scheint ein Secret zu sein, aber steht im Klartext in environment.", svc_name))

        svc_publishes_443 = False
        if isinstance(ports, list):
            for p in ports:
                for published, proto in parse_ports_entry(p):
                    if published == 443 and proto == "tcp":
                        svc_publishes_443 = True
                        break
        if svc_publishes_443 and not has_cert_hint(svc):
            findings.append(warn("443 veröffentlicht, aber kein offensichtliches Zertifikat/Secret (pem/crt/key) gemountet.", svc_name))

    if any_http_published and not any_https_published:
        findings.append(warn("Es wird HTTP (Port 80) veröffentlicht, aber nirgends HTTPS (Port 443) – Verbindung vermutlich unverschlüsselt.", None))

    if not findings:
        findings.append(f"{GREEN}✔ Keine Warnungen gefunden (basierend auf den implementierten Checks).{RESET}")
    return findings

def fallback_text_checks(text: str) -> List[str]:
    findings: List[str] = []
    for m in re.finditer(r"^\s*image:\s*([^\s#]+)", text, flags=re.M):
        img = m.group(1)
        if "@sha256:" in img:
            findings.append(warn(f"Image '{img}' ist per Digest gepinnt – entspricht nicht ':latest' (deine Regel)."))
        elif ":" in img:
            tag = img.rsplit(":", 1)[1]
            if tag.lower() != "latest":
                findings.append(warn(f"Image '{img}' nutzt keinen ':latest'-Tag."))

    if re.search(r"^\s*privileged:\s*true\s*$", text, flags=re.M | re.I):
        findings.append(warn("privileged: true gesetzt."))

    if "docker.sock" in text:
        findings.append(warn("Docker-Socket gemountet."))

    if re.search(r"^\s*network_mode:\s*host\s*$", text, flags=re.M | re.I):
        findings.append(warn("network_mode: host verwendet."))

    has80 = re.search(r"published:\s*80\b", text) or re.search(r"[:\s]80[:\s]", text)
    has443 = re.search(r"published:\s*443\b", text) or re.search(r"[:\s]443[:\s]", text)
    if has80 and not has443:
        findings.append(warn("HTTP (80) veröffentlicht, aber kein HTTPS (443) gefunden – Verbindung vermutlich unverschlüsselt."))

    if "healthcheck:" not in text:
        findings.append(warn("Kein Healthcheck gefunden (Textsuche)."))

    if not findings:
        findings.append(f"{GREEN}✔ Keine Warnungen in der Fallback-Textanalyse gefunden.{RESET}")
    findings.append(f"{DIM}Hinweis: Für umfassendere Checks bitte PyYAML installieren: 'pip install pyyaml'.{RESET}")
    return findings

def main():
    path = ask_path()
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    if YAML_AVAILABLE:
        data = load_yaml(text)
    else:
        data = None

    print(f"\n{BLUE}Analysiere:{RESET} {path}\n")

    if data and isinstance(data, dict) and ("services" in data):
        findings = run_checks(data)
    else:
        if not YAML_AVAILABLE:
            print(f"{YELLOW}PyYAML nicht verfügbar – wechsle auf Fallback-Textanalyse.{RESET}")
        else:
            print(f"{YELLOW}Konnte YAML nicht vollständig parsen – wechsle auf Fallback-Textanalyse.{RESET}")
        findings = fallback_text_checks(text)

    for line in findings:
        print(line)

    warn_count = sum(1 for l in findings if l.startswith(YELLOW+"WARN") or l.startswith(RED+"WARN") or l.startswith(RED+"ERROR"))
    print(f"\n{BLUE}Fertig.{RESET} Gefundene Warnungen: {warn_count}")
    if not YAML_AVAILABLE:
        print(f"{DIM}Tipp: 'pip install pyyaml' für detailliertere Prüfungen.{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAbgebrochen.")
        sys.exit(130)