#!/usr/bin/env python3
"""
Netkido — agente de sede.

  netkido-agent enroll --portal URL --token TOKEN   inscribe la sede (lo usa el instalador)
  netkido-agent apply  [--cached]                   aplica la configuración (la del portal o la guardada)
  netkido-agent run                                 demonio: heartbeat, configuración y jobs
  netkido-agent status                              resumen local

La sede aplica el estado deseado que le da el portal: túnel WireGuard con el hub,
VRF del tenant con su L3VNI (EVPN type-5), LAN local con DHCP, MSS clamping y
FRR. La clave privada de WireGuard se genera aquí y nunca sale de la sede.

Solo usa la biblioteca estándar de Python (3.9+).
"""
import argparse
import base64
import datetime
import errno
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

AGENT_VERSION = "2.4.1"

# OpenWrt: procd en vez de systemd, /var en RAM y memoria flash (pocas escrituras).
OPENWRT = os.path.exists("/etc/openwrt_release")
INIT_DIR = "/etc/init.d"          # OpenWrt: scripts de los servicios (procd)
CONF_DIR = os.environ.get("NETKIDO_CONF_DIR", "/etc/netkido")
STATE_DIR = os.environ.get("NETKIDO_STATE_DIR", os.path.join(CONF_DIR, "state") if OPENWRT else "/var/lib/netkido")
AGENT_CONF = os.path.join(CONF_DIR, "agent.json")
API_PREFIX = "/api/agent/v1"

HEARTBEAT_SEC = 60
POLL_MAX_SEC = 30
POLL_FAST_SEC = 5
APPLY_RETRY_SEC = 120
MAX_CONCURRENT_JOBS = 3
MAX_JOB_TIMEOUT = 600
MAX_OUTPUT_BYTES = 512_000
HTTP_TIMEOUT = 30

# ── Idioma de los mensajes ─────────────────────────────────────────────
# El texto fuente es el español; EN traduce los mensajes que ve el cliente
# (instalación, log del agente, errores que se envían al portal).
LANGS = {"es", "en"}
LANG = "es"
EN = {
    "sin conexión con el portal: {err}": "no connection to the portal: {err}",
    "configuración del portal no válida: {err}": "invalid configuration from the portal: {err}",
    "falta la clave privada de WireGuard ({path})": "WireGuard private key missing ({path})",
    "Configuración v{version} aplicada (VRF {vrf}, L3VNI {l3vni}, LAN {lan})": "Configuration v{version} applied (VRF {vrf}, L3VNI {l3vni}, LAN {lan})",
    "eliminada interfaz sobrante {name}": "removed leftover interface {name}",
    "{iface} sale de la LAN": "{iface} removed from the LAN",
    "la interfaz LAN {iface} no existe (se reintentará en la próxima aplicación)": "LAN interface {iface} does not exist (will retry on the next apply)",
    "{iface} es la salida a Internet: no se mete en la LAN": "{iface} is the Internet uplink: it is not added to the LAN",
    "nft no está instalado: sin MSS clamping": "nft is not installed: no MSS clamping",
    "{tool} deja de gestionar: {ifaces}": "{tool} no longer manages: {ifaces}",
    "FRR no responde": "FRR is not responding",
    "{iface} es parte de {bridge} (configuración de OpenWrt): quítalo de ahí en LuCI (Red → Interfaces → Dispositivos) para usarlo en la LAN de Netkido":
        "{iface} belongs to {bridge} (OpenWrt configuration): remove it there in LuCI (Network → Interfaces → Devices) to use it in the Netkido LAN",
    "la detección en la sede no está disponible en OpenWrt": "site intrusion detection is not available on OpenWrt",
    "bgpd no está en marcha: reiniciando FRR": "bgpd is not running: restarting FRR",
    "bgpd no está en marcha": "bgpd is not running",
    "Error aplicando la configuración v{version}: {err}": "Error applying configuration v{version}: {err}",
    "configuración v{version} aplicada": "configuration v{version} applied",
    "evento {kind} no enviado: {err}": "event {kind} not sent: {err}",
    "El portal indica que la sede está desactivada": "The portal reports that this site is disabled",
    "Conectado con el portal (config v{version}, jobs pendientes {jobs})": "Connected to the portal (config v{version}, pending jobs {jobs})",
    "No se pudo descargar la configuración: {err}": "Could not download the configuration: {err}",
    "Secreto rotado; el portal lo confirmará con la próxima petición": "Secret rotated; the portal will confirm it on the next request",
    "Actualizando el agente {old} → {new}": "Updating the agent {old} → {new}",
    "SHA-256 no coincide": "SHA-256 mismatch",
    "el fichero no declara la versión anunciada": "the file does not declare the announced version",
    "Actualización a {new} fallida: {err}": "Update to {new} failed: {err}",
    "Agente actualizado; reiniciando": "Agent updated; restarting",
    "Job {id} no se ejecuta: límite de {max} simultáneos": "Job {id} not run: limit of {max} concurrent jobs",
    "La sede tenía demasiados jobs en curso.": "The site had too many jobs running.",
    "[{id}] no se pudo enviar el resultado: {err}": "[{id}] could not send the result: {err}",
    "intérprete no disponible: {type}": "interpreter not available: {type}",
    "[{id}] terminado con código {code}": "[{id}] finished with exit code {code}",
    "Netkido agent {version} · sede {node} · {portal}": "Netkido agent {version} · site {node} · {portal}",
    "Deteniendo; esperando a los jobs en curso": "Stopping; waiting for running jobs",
    "Inscripción rechazada: {err}": "Enrolment rejected: {err}",
    "Sede inscrita: {node}": "Site enrolled: {node}",
    "No hay configuración guardada": "No saved configuration",
    "{err}; se aplica la configuración guardada": "{err}; applying the saved configuration",
    "Sede sin inscribir ({path}). Usa el comando de instalación del panel.": "Site not enrolled ({path}). Use the install command from the dashboard.",
    "El agente tiene que ejecutarse como root": "The agent must run as root",
    "Agente de sede Netkido": "Netkido site agent",
    "inscribir la sede con un token de instalación": "enrol the site with an install token",
    "no verificar TLS (solo laboratorio)": "do not verify TLS (lab only)",
    "idioma de los mensajes del agente": "language of the agent's messages",
    "aplicar la configuración": "apply the configuration",
    "usar la última guardada sin preguntar al portal": "use the last saved one without asking the portal",
    "ejecutar el agente": "run the agent",
    "estado local": "local status",
}


def set_lang(lang):
    global LANG
    LANG = lang if lang in LANGS else "es"


def _(msg, **kw):
    text = EN.get(msg, msg) if LANG == "en" else msg
    return text.format(**kw) if kw else text


DEFAULT_SETTINGS = {
    "portal": "",
    "node_id": "",
    "lang": "es",           # idioma de los mensajes (es / en); lo fija el instalador
    "tls_verify": True,
    "secret_file": os.path.join(CONF_DIR, "secret"),
    "wg_key_file": os.path.join(CONF_DIR, "wg.key"),
    "frr_conf": "/etc/frr/frr.conf",
    # Gestores de red del sistema: se les quitan las interfaces de Netkido y los puertos LAN
    # (Armbian, por ejemplo, pone DHCP en todas las Ethernet con NetworkManager o systemd-networkd).
    "nm_conf_dir": "/etc/NetworkManager/conf.d",
    "networkd_dir": "/etc/systemd/network",
    "frr_daemons": "/etc/frr/daemons",
    "frr_reload": "/usr/lib/frr/frr-reload.py",
    "vtysh": "vtysh",
    "vty_socket": "",           # laboratorio
    "manage_services": True,    # systemctl (frr, netkido-dhcp)
    "dhcp": True,
    "dnsmasq_conf": os.path.join(CONF_DIR, "dnsmasq-lan.conf"),
    "sysctl_file": "/etc/sysctl.d/90-netkido.conf",
    "log_file": "" if OPENWRT else "/var/log/netkido/agent.log",   # OpenWrt: procd lo manda a logread
}

log = logging.getLogger("netkido-agent")


# ─── Utilidades ──────────────────────────────────────────────────────────────

def setup_logging(log_file=None, level="INFO"):
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%dT%H:%M:%S")
    root = logging.getLogger()
    root.setLevel(getattr(logging, level))
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(fmt)
    root.handlers = [h]
    if log_file and not os.environ.get("INVOCATION_ID"):   # con systemd ya va al journal
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError:
            pass


# OpenWrt: el «ip» de BusyBox no sabe de VRF, VXLAN ni JSON. El completo es /usr/libexec/ip-full
# (ip-full); normalmente /sbin/ip apunta a él, pero no siempre: se usa directamente si existe.
IP_FULL = "/usr/libexec/ip-full"


def sh(cmd, check=True, input_text=None, timeout=60):
    if cmd and cmd[0] == "ip" and os.path.exists(IP_FULL):
        cmd = [IP_FULL] + list(cmd[1:])
    p = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} → {p.returncode}: {(p.stderr or p.stdout).strip()[:1000]}")
    return p


_TCP_MD5 = None


def tcp_md5_supported():
    """¿Admite el kernel TCP MD5 (RFC 2385, CONFIG_TCP_MD5SIG)? Algunos kernels de placas SBC
    vienen sin él; con esas sedes la sesión BGP va sin contraseña (sigue dentro de WireGuard)."""
    global _TCP_MD5
    if _TCP_MD5 is None:
        # struct tcp_md5sig: sockaddr_storage (128) · flags · prefixlen · keylen (u16) · ifindex (u32) · key[80]
        addr = socket.AF_INET.to_bytes(2, sys.byteorder) + b"\0\0" + socket.inet_aton("127.0.0.1")
        sig = addr.ljust(128, b"\0") + bytes([0, 0]) + (8).to_bytes(2, sys.byteorder) + bytes(4) + b"netkido!".ljust(80, b"\0")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as so:
                so.setsockopt(socket.IPPROTO_TCP, 14, sig)    # TCP_MD5SIG
            _TCP_MD5 = True
        except OSError as e:
            _TCP_MD5 = e.errno != errno.ENOPROTOOPT     # «Protocol not available»: kernel sin MD5
    return _TCP_MD5


def svc(action, name, check=True):
    """Arranca, para o consulta un servicio con systemd o, en OpenWrt, con su script de /etc/init.d.
    action: start (y habilitar al arrancar), restart, stop (y deshabilitar) o active (→ bool)."""
    if OPENWRT:
        init = os.path.join(INIT_DIR, name)
        if not os.path.exists(init):
            if action == "active":
                return False
            if check:
                raise RuntimeError(f"{init} no existe")
            return None
        if action == "active":
            # procd tiene «running»; FRR (no es procd) tiene «status».
            return any(sh([init, cmd], check=False).returncode == 0 for cmd in ("running", "status"))
        if action == "start":
            sh([init, "enable"], check=False)
            return sh([init, "start"], check=check)
        if action == "stop":
            sh([init, "stop"], check=False)
            return sh([init, "disable"], check=False)
        return sh([init, action], check=check)
    if action == "active":
        return sh(["systemctl", "is-active", "--quiet", name], check=False).returncode == 0
    if action == "start":
        return sh(["systemctl", "enable", "--now", name], check=check)
    if action == "stop":
        return sh(["systemctl", "disable", "--now", name], check=False)
    return sh(["systemctl", action, name], check=check)


def atomic_write(path, content, mode=0o600):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".nk-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read(path, default=None):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return default


def load_settings():
    s = dict(DEFAULT_SETTINGS)
    raw = read(AGENT_CONF)
    if raw:
        s.update(json.loads(raw))
    return s


def save_settings(s):
    keep = {k: v for k, v in s.items() if k in DEFAULT_SETTINGS}
    atomic_write(AGENT_CONF, json.dumps(keep, indent=2) + "\n", 0o600)


def iface_exists(name):
    return os.path.exists(f"/sys/class/net/{name}")


def link_info(name):
    p = sh(["ip", "-d", "-j", "link", "show", "dev", name], check=False)
    if p.returncode != 0:
        return None
    try:
        return json.loads(p.stdout)[0]
    except (ValueError, IndexError):
        return None


# ─── Portal (HTTP firmado) ───────────────────────────────────────────────────

class PortalError(Exception):
    def __init__(self, status, message):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class Portal:
    def __init__(self, settings):
        self.base = settings["portal"].rstrip("/")
        self.node_id = settings.get("node_id", "")
        self.secret_file = settings["secret_file"]
        self.ctx = ssl.create_default_context()
        if not settings.get("tls_verify", True):
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def secret(self):
        return (read(self.secret_file, "") or "").strip()

    def _sign(self, method, path, body):
        ts = str(int(time.time()))
        nonce = secrets.token_urlsafe(18)
        payload = "\n".join(["NK1", method, path, ts, nonce, hashlib.sha256(body).hexdigest()])
        sig = hmac.new(self.secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
        return {"X-Netkido-Node": self.node_id, "X-Netkido-Timestamp": ts,
                "X-Netkido-Nonce": nonce, "X-Netkido-Signature": sig}

    def request(self, method, path, payload=None, signed=True, raw=False, timeout=HTTP_TIMEOUT):
        url = self.base + path
        body = b"" if payload is None else json.dumps(payload).encode()
        headers = {"User-Agent": f"netkido-agent/{AGENT_VERSION}", "Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if signed:
            headers.update(self._sign(method, urllib.parse.urlsplit(url).path, body))
        req = urllib.request.Request(url, data=body if method != "GET" else None, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ctx if url.startswith("https") else None) as r:
                data = r.read()
                if raw:
                    return data, dict(r.headers)
                return json.loads(data or b"{}")
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read() or b"{}").get("message") or e.reason
            except ValueError:
                msg = e.reason
            raise PortalError(e.code, msg) from None
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
            raise PortalError(0, _("sin conexión con el portal: {err}", err=getattr(e, 'reason', e))) from None

    def get(self, path, **kw):
        return self.request("GET", API_PREFIX + path, **kw)

    def post(self, path, payload=None, **kw):
        return self.request("POST", API_PREFIX + path, payload if payload is not None else {}, **kw)


# ─── Configuración de red ────────────────────────────────────────────────────

RE_IFACE = re.compile(r"^[a-zA-Z][a-zA-Z0-9._-]{0,14}$")


def validate_config(c):
    """El portal es de confianza, pero un error aquí no debe dejar la sede a medias."""
    try:
        assert c.get("schema") == 1
        wg, ov, lan, bgp = c["wireguard"], c["overlay"], c["lan"], c["bgp"]
        ipaddress.IPv4Address(wg["address"])
        ipaddress.IPv4Address(wg["hub"]["ip"])
        ipaddress.IPv4Network(wg["hub"]["allowed_ips"])
        assert len(base64.b64decode(wg["hub"]["public_key"])) == 32
        assert re.match(r"^[A-Za-z0-9.-]+:\d{1,5}$", wg["hub"]["endpoint"])
        for name in (wg["interface"], ov["vrf"], ov["bridge"], ov["vxlan"], lan["bridge"]):
            assert RE_IFACE.match(name), name
        assert 1 <= int(ov["l3vni"]) <= 16777215 and 1 <= int(ov["table"]) <= 4294967295
        assert 576 <= int(ov["vxlan_mtu"]) <= 9000 and 576 <= int(wg["mtu"]) <= 9000
        ipaddress.IPv4Interface(lan["address"])
        for i in lan["interfaces"]:
            assert RE_IFACE.match(i), i
        assert bgp.get("password") is None or re.match(r"^[A-Za-z0-9]{16,80}$", bgp["password"])
        assert re.match(r"^[A-Za-z0-9-]{1,63}$", c["node"]["hostname"])
        int(c["version"])
    except (AssertionError, KeyError, TypeError, ValueError) as e:
        raise RuntimeError(_("configuración del portal no válida: {err}", err=repr(e)))


class Applier:
    def __init__(self, settings):
        self.s = settings

    # ---- helpers
    def _wg_private_key(self):
        key = (read(self.s["wg_key_file"], "") or "").strip()
        if not key:
            raise RuntimeError(_("falta la clave privada de WireGuard ({path})", path=self.s['wg_key_file']))
        return key

    def apply(self, c, previous=None):
        validate_config(c)
        steps = [("sysctl", self.sysctl), ("wireguard", self.wireguard), ("overlay", self.overlay),
                 ("unmanaged", self.unmanaged), ("lan", self.lan), ("mss", self.mss), ("frr", self.frr),
                 ("dhcp", self.dhcp)]
        for name, fn in steps:
            try:
                fn(c, previous)
            except Exception as e:
                raise RuntimeError(f"{name}: {e}") from None
        log.info(_("Configuración v{version} aplicada (VRF {vrf}, L3VNI {l3vni}, LAN {lan})",
                   version=c['version'], vrf=c['overlay']['vrf'], l3vni=c['overlay']['l3vni'], lan=c['lan']['address']))

    def sysctl(self, c, _prev):
        content = "net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.rp_filter = 2\nnet.ipv4.conf.default.rp_filter = 2\n"
        if read(self.s["sysctl_file"]) != content:
            atomic_write(self.s["sysctl_file"], content, 0o644)
        for kv in ("net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.default.rp_filter=2"):
            sh(["sysctl", "-qw", kv])

    def wireguard(self, c, _prev):
        wg = c["wireguard"]
        dev = wg["interface"]
        hub = wg["hub"]
        conf = "\n".join([
            "[Interface]", f"PrivateKey = {self._wg_private_key()}", "",
            "[Peer]", f"PublicKey = {hub['public_key']}", f"Endpoint = {hub['endpoint']}",
            f"AllowedIPs = {hub['allowed_ips']}", f"PersistentKeepalive = {int(hub['keepalive'])}", ""])
        if not iface_exists(dev):
            sh(["ip", "link", "add", dev, "type", "wireguard"])
        fd, tmp = tempfile.mkstemp(prefix="nk-wg-")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(conf)
            sh(["wg", "syncconf", dev, tmp])   # solo cambia lo que difiere: no corta el túnel
        finally:
            os.unlink(tmp)
        want = f"{wg['address']}/32"
        cur = sh(["ip", "-4", "-o", "addr", "show", "dev", dev], check=False).stdout.split()
        for i, tok in enumerate(cur):
            if tok == "inet" and cur[i + 1] != want:
                sh(["ip", "addr", "del", cur[i + 1], "dev", dev], check=False)
        sh(["ip", "addr", "replace", want, "dev", dev])
        sh(["ip", "link", "set", dev, "mtu", str(int(wg["mtu"])), "up"])
        sh(["ip", "route", "replace", hub["allowed_ips"], "dev", dev, "src", wg["address"]])

    def overlay(self, c, _prev):
        ov = c["overlay"]
        vrf, table, vni = ov["vrf"], int(ov["table"]), int(ov["l3vni"])
        br, vx, mtu = ov["bridge"], ov["vxlan"], int(ov["vxlan_mtu"])
        local = c["wireguard"]["address"]
        for m in ("vrf", "vxlan", "bridge"):
            sh(["modprobe", m], check=False)
        # Una sede pertenece a un solo tenant: cualquier otra VRF/puente de Netkido sobra.
        for name in os.listdir("/sys/class/net"):
            if (name.startswith("TENANT-") and name != vrf) or (re.match(r"^nk(br|vx)\d+$", name) and name not in (br, vx)):
                sh(["ip", "link", "del", name], check=False)
                log.info(_("eliminada interfaz sobrante {name}", name=name))

        info = link_info(vrf)
        if info and info.get("linkinfo", {}).get("info_data", {}).get("table") != table:
            sh(["ip", "link", "del", vrf])
            info = None
        if not info:
            sh(["ip", "link", "add", vrf, "type", "vrf", "table", str(table)])
        sh(["ip", "link", "set", vrf, "up"])

        vinfo = link_info(vx)
        d = (vinfo or {}).get("linkinfo", {}).get("info_data", {})
        if vinfo and (d.get("id") != vni or d.get("local") != local or d.get("port") != 4789
                      or vinfo.get("mtu") != mtu or vinfo.get("master") != br):
            sh(["ip", "link", "del", vx])
            vinfo = None
        if not iface_exists(br):
            sh(["ip", "link", "add", br, "type", "bridge"])
        sh(["ip", "link", "set", br, "master", vrf, "addrgenmode", "none"])
        sh(["ip", "link", "set", br, "mtu", str(mtu)])
        if not vinfo:
            sh(["ip", "link", "add", vx, "type", "vxlan", "id", str(vni), "local", local,
                "dstport", "4789", "nolearning"])
            sh(["ip", "link", "set", vx, "mtu", str(mtu)])
            sh(["ip", "link", "set", vx, "master", br, "addrgenmode", "none"])
            sh(["ip", "link", "set", vx, "type", "bridge_slave", "neigh_suppress", "on", "learning", "off"])
        sh(["ip", "link", "set", vx, "up"])
        sh(["ip", "link", "set", br, "up"])

    def unmanaged(self, c, _prev):
        """Que NetworkManager y systemd-networkd no toquen las interfaces de Netkido ni los puertos
        LAN: si les ponen DHCP o las reconfiguran, se rompe el puente de la LAN."""
        uplink = default_route_iface()
        names = ["nk*", "TENANT-*"] + sorted(i for i in set(c["lan"]["interfaces"]) if i != uplink)
        nm_dir, nd_dir = self.s.get("nm_conf_dir"), self.s.get("networkd_dir")
        # Solo si el gestor está instalado (existe su directorio de configuración).
        if nm_dir and os.path.isdir(os.path.dirname(nm_dir)):
            path = os.path.join(nm_dir, "90-netkido.conf")
            content = ("# Netkido: interfaces que NetworkManager no debe gestionar (lo escribe netkido-agent)\n"
                       "[keyfile]\nunmanaged-devices=" + ";".join(f"interface-name:{n}" for n in names) + "\n")
            if read(path) != content:
                atomic_write(path, content, 0o644)
                if shutil.which("nmcli"):
                    sh(["nmcli", "general", "reload", "conf"], check=False)
                log.info(_("{tool} deja de gestionar: {ifaces}", tool="NetworkManager", ifaces=" ".join(names)))
            if shutil.which("nmcli"):
                for i in names[2:]:
                    if iface_exists(i):
                        sh(["nmcli", "device", "set", i, "managed", "no"], check=False)
        if nd_dir and os.path.isdir(os.path.dirname(nd_dir)):
            # 00-…: va antes que los ficheros de netplan (10-netplan-…), así que gana.
            path = os.path.join(nd_dir, "00-netkido.network")
            content = ("# Netkido: interfaces que systemd-networkd no debe gestionar (lo escribe netkido-agent)\n"
                       "[Match]\nName=" + " ".join(names) + "\n\n[Link]\nUnmanaged=yes\n")
            if read(path) != content:
                atomic_write(path, content, 0o644)
                if shutil.which("networkctl"):
                    sh(["networkctl", "reload"], check=False)
                log.info(_("{tool} deja de gestionar: {ifaces}", tool="systemd-networkd", ifaces=" ".join(names)))

    def lan(self, c, previous):
        lan, vrf = c["lan"], c["overlay"]["vrf"]
        br = lan["bridge"]
        if not iface_exists(br):
            sh(["ip", "link", "add", br, "type", "bridge"])
        sh(["ip", "link", "set", br, "master", vrf])
        want = lan["address"]
        for tok in re.findall(r"inet (\S+)", sh(["ip", "-4", "-o", "addr", "show", "dev", br]).stdout):
            if tok != want:
                sh(["ip", "addr", "del", tok, "dev", br], check=False)
        sh(["ip", "addr", "replace", want, "dev", br])
        sh(["ip", "link", "set", br, "up"])
        wanted = set(lan["interfaces"])
        old = set((previous or {}).get("lan", {}).get("interfaces", [])) - wanted
        for i in sorted(old):
            if iface_exists(i):
                sh(["ip", "link", "set", i, "nomaster"], check=False)
                log.info(_("{iface} sale de la LAN", iface=i))
        for i in sorted(wanted):
            if not iface_exists(i):
                log.warning(_("la interfaz LAN {iface} no existe (se reintentará en la próxima aplicación)", iface=i))
                continue
            if i == default_route_iface():
                log.error(_("{iface} es la salida a Internet: no se mete en la LAN", iface=i))
                continue
            master = (link_info(i) or {}).get("master")
            if OPENWRT and master and master != br:
                log.error(_("{iface} es parte de {bridge} (configuración de OpenWrt): quítalo de ahí en LuCI "
                            "(Red → Interfaces → Dispositivos) para usarlo en la LAN de Netkido", iface=i, bridge=master))
                continue
            if master != br:
                # Un puerto del puente no lleva IP propia (p. ej. la que le dio DHCP el gestor de red
                # del sistema antes de quitársela).
                sh(["ip", "addr", "flush", "dev", i, "scope", "global"], check=False)
            sh(["ip", "link", "set", i, "master", br])
            sh(["ip", "link", "set", i, "up"])

    def mss(self, c, _prev):
        if not shutil.which("nft"):
            log.warning(_("nft no está instalado: sin MSS clamping"))
            return
        sh(["nft", "-f", "-"], input_text="""table inet netkido_cpe
delete table inet netkido_cpe
table inet netkido_cpe {
  chain forward {
    type filter hook forward priority mangle; policy accept;
    tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu comment "netkido: MSS clamping"
  }
}
""")

    def frr_conf(self, c):
        b, ov = c["bgp"], c["overlay"]
        rid = b["router_id"]
        return "\n".join([
            "! Generado por netkido-agent — NO editar (se sobrescribe)",
            "frr defaults traditional",
            f"hostname {c['node']['hostname']}",
            "log syslog informational",
            "service integrated-vtysh-config",
            "!",
            f"vrf {ov['vrf']}",
            f" vni {int(ov['l3vni'])}",
            "exit-vrf",
            "!",
            f"router bgp {int(b['asn'])}",
            f" bgp router-id {rid}",
            " no bgp default ipv4-unicast",
            f" neighbor {b['neighbor']} remote-as {int(b['asn'])}",
            *([f" neighbor {b['neighbor']} password {b['password']}"] if b.get("password") and tcp_md5_supported() else []),
            f" neighbor {b['neighbor']} update-source {rid}",
            f" neighbor {b['neighbor']} timers 10 30",
            " !",
            " address-family l2vpn evpn",
            f"  neighbor {b['neighbor']} activate",
            "  advertise-all-vni",
            " exit-address-family",
            "exit",
            "!",
            f"router bgp {int(b['asn'])} vrf {ov['vrf']}",
            f" bgp router-id {rid}",
            " !",
            " address-family ipv4 unicast",
            "  redistribute connected",
            " exit-address-family",
            " !",
            " address-family l2vpn evpn",
            "  advertise ipv4 unicast",
            " exit-address-family",
            "exit",
            "!",
            "line vty",
            "exit",
            ""])

    def _vty(self):
        return [self.s["vtysh"]] + (["--vty_socket", self.s["vty_socket"]] if self.s.get("vty_socket") else [])

    def frr(self, c, _prev):
        content = self.frr_conf(c)
        conf = self.s["frr_conf"]
        daemons = read(self.s["frr_daemons"])
        if daemons and re.search(r"^bgpd=no", daemons, re.M):
            atomic_write(self.s["frr_daemons"], re.sub(r"^bgpd=no", "bgpd=yes", daemons, flags=re.M), 0o640)
            if self.s.get("manage_services"):
                svc("restart", "frr")
        changed = read(conf) != content
        if changed:
            atomic_write(conf, content, 0o640)
            try:
                shutil.chown(conf, "frr", "frr")
            except (LookupError, PermissionError, OSError):
                pass
        running = sh(self._vty() + ["-c", "show version"], check=False).returncode == 0
        if not running:
            if self.s.get("manage_services"):
                svc("start", "frr")
                return
            raise RuntimeError(_("FRR no responde"))
        # bgpd tiene que estar en marcha: si FRR arrancó antes de activarlo en «daemons» (apt lo
        # arranca al instalarse con bgpd=no), «show running-config» no tiene BGP y frr-reload no
        # puede aplicarlo. Se reinicia FRR, que carga frr.conf completo al arrancar.
        d = sh(self._vty() + ["-c", "show daemons"], check=False)
        if d.returncode == 0 and "bgpd" not in d.stdout.split():
            if self.s.get("manage_services"):
                log.warning(_("bgpd no está en marcha: reiniciando FRR"))
                svc("restart", "frr")
                return
            raise RuntimeError(_("bgpd no está en marcha"))
        cmd = [sys.executable, self.s["frr_reload"], "--reload", conf]
        if self.s.get("vty_socket"):
            cmd[2:2] = ["--vty_socket", self.s["vty_socket"], "--bindir", os.path.dirname(shutil.which(self.s["vtysh"]) or self.s["vtysh"])]
        p = sh(cmd, check=False, timeout=120)
        if p.returncode != 0:
            raise RuntimeError(f"frr-reload: {(p.stderr or p.stdout).strip()[-1000:]}")

    def dhcp(self, c, _prev):
        d = c["lan"]["dhcp"]
        conf = self.s["dnsmasq_conf"]
        if not self.s.get("dhcp", True) or not self.s.get("manage_services"):
            return
        if not d.get("enabled"):
            svc("stop", "netkido-dhcp")
            return
        gw = c["lan"]["address"].split("/")[0]
        # OpenWrt: las concesiones en RAM (/tmp), no en la flash.
        leases = "/tmp/netkido-dnsmasq.leases" if OPENWRT else f"{STATE_DIR}/dnsmasq.leases"
        content = "\n".join([
            "# Generado por netkido-agent — DHCP de la LAN de la sede",
            "port=0", "bind-interfaces", f"interface={c['lan']['bridge']}", "except-interface=lo",
            f"dhcp-range={d['start']},{d['end']},{d['lease']}",
            f"dhcp-option=option:router,{gw}",
            *( [f"dhcp-option=option:dns-server,{','.join(d['dns'])}"] if d.get("dns") else [] ),
            "dhcp-authoritative", f"dhcp-leasefile={leases}", ""])
        changed = read(conf) != content
        if changed:
            atomic_write(conf, content, 0o644)
        if changed or not svc("active", "netkido-dhcp"):
            svc("start", "netkido-dhcp")
            svc("restart", "netkido-dhcp")


def default_route_iface():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if len(p) > 1 and p[1] == "00000000":
                    return p[0]
    except OSError:
        pass
    return ""


# ─── Métricas ────────────────────────────────────────────────────────────────

class Metrics:
    SKIP = ("lo", "nk", "TENANT-", "docker", "veth", "virbr")

    def __init__(self, wg_iface):
        self.wg = wg_iface
        self.prev_net = None
        self.prev_cpu = None

    @staticmethod
    def _iface_bytes(name):
        try:
            rx = int(read(f"/sys/class/net/{name}/statistics/rx_bytes", "0"))
            tx = int(read(f"/sys/class/net/{name}/statistics/tx_bytes", "0"))
            return rx, tx
        except ValueError:
            return 0, 0

    def collect(self):
        m = {}
        now = time.monotonic()
        if iface_exists(self.wg):
            rx, tx = self._iface_bytes(self.wg)
            if self.prev_net:
                dt = now - self.prev_net[0]
                if dt > 0:
                    m["rx_mbps"] = round(max(0, rx - self.prev_net[1]) * 8 / dt / 1e6, 3)
                    m["tx_mbps"] = round(max(0, tx - self.prev_net[2]) * 8 / dt / 1e6, 3)
            self.prev_net = (now, rx, tx)
        try:
            f = [int(x) for x in read("/proc/stat").splitlines()[0].split()[1:]]
            idle, total = f[3] + f[4], sum(f)
            if self.prev_cpu and total > self.prev_cpu[1]:
                m["cpu_pct"] = round(100 * (1 - (idle - self.prev_cpu[0]) / (total - self.prev_cpu[1])), 1)
            self.prev_cpu = (idle, total)
        except Exception:
            pass
        try:
            mem = {k.strip(): int(v.split()[0]) for k, v in (l.split(":", 1) for l in read("/proc/meminfo").splitlines())}
            m["mem_pct"] = round(100 * (1 - mem.get("MemAvailable", 0) / mem["MemTotal"]), 1)
        except Exception:
            pass
        try:
            p = sh(["ping", "-c", "3", "-W", "2", "-q", "100.64.0.1"], check=False, timeout=15)
            r = re.search(r"= [\d.]+/([\d.]+)/", p.stdout)
            if r:
                m["latency_ms"] = float(r.group(1))
        except Exception:
            pass
        try:
            m["uptime"] = int(float(read("/proc/uptime", "0").split()[0]))
        except Exception:
            pass
        return m

    def interfaces(self):
        out = []
        try:
            data = json.loads(sh(["ip", "-j", "addr"], check=False).stdout or "[]")
        except ValueError:
            return out
        gw = default_route_iface()
        for i in data:
            name = i.get("ifname", "")
            if not name or name.startswith(self.SKIP) or i.get("link_type") not in ("ether", None):
                continue
            ip4 = next((f"{a['local']}/{a['prefixlen']}" for a in i.get("addr_info", []) if a.get("family") == "inet"), None)
            out.append({"name": name, "ip": ip4, "mac": i.get("address"), "is_gw": name == gw,
                        "up": "UP" in i.get("flags", [])})
        return out[:32]



# ─── Agente ──────────────────────────────────────────────────────────────────

class Agent:
    def __init__(self, settings):
        self.s = settings
        self.portal = Portal(settings)
        self.applier = Applier(settings)
        self.stop = threading.Event()
        self.jobs = {}
        self.job_sem = threading.Semaphore(MAX_CONCURRENT_JOBS)
        self.wanted_version = None
        self.apply_error = ""
        self.apply_failed_at = 0.0
        self.apply_lock = threading.Lock()
        self.update_failed = {}
        self.disabled = False
        cfg = self.cached_config()
        self.metrics = Metrics((cfg or {}).get("wireguard", {}).get("interface", "nk0"))

    # ---- estado local
    @staticmethod
    def cached_config():
        raw = read(os.path.join(STATE_DIR, "config.json"))
        return json.loads(raw) if raw else None

    @staticmethod
    def applied_version():
        try:
            return int(read(os.path.join(STATE_DIR, "applied_version"), "").strip())
        except ValueError:
            return None

    def apply_config(self, config):
        with self.apply_lock:
            previous = self.cached_config()
            try:
                self.applier.apply(config, previous)
            except Exception as e:
                self.apply_error = str(e)[:2000]
                self.apply_failed_at = time.monotonic()
                log.error(_("Error aplicando la configuración v{version}: {err}", version=config.get('version'), err=self.apply_error))
                atomic_write(os.path.join(STATE_DIR, "config.json"), json.dumps(config, indent=1), 0o600)
                return False
            atomic_write(os.path.join(STATE_DIR, "config.json"), json.dumps(config, indent=1), 0o600)
            atomic_write(os.path.join(STATE_DIR, "applied_version"), str(int(config["version"])), 0o644)
            self.apply_error = ""
            return True

    def sync_config(self):
        cfg = self.portal.get("/config")
        if self.apply_config(cfg):
            self.event("apply_ok", _("configuración v{version} aplicada", version=cfg['version']))
        # Si falla, el error viaja en el siguiente heartbeat (apply_error).

    def event(self, kind, message=""):
        try:
            self.portal.post("/events", {"type": kind, "message": message[:480]})
        except PortalError as e:
            log.debug(_("evento {kind} no enviado: {err}", kind=kind, err=e))

    # ---- heartbeat
    def heartbeat(self, first=False):
        payload = {
            "agent_version": AGENT_VERSION,
            "bgp_md5": tcp_md5_supported(),
            "applied_config_version": self.applied_version(),
            "apply_error": self.apply_error,
            "running_jobs": len(self.jobs),
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()} · {os_pretty()}",
            "metrics": self.metrics.collect(),
            "interfaces": self.metrics.interfaces(),
        }
        try:
            r = self.portal.post("/heartbeat", payload)
        except PortalError as e:
            if e.status == 403:
                if not self.disabled:
                    log.warning(_("El portal indica que la sede está desactivada"))
                self.disabled = True
            elif e.status != 429:
                log.warning(f"Heartbeat: {e}")
            return
        self.disabled = False
        if r.get("rotate_secret"):
            self.rotate_secret(r["rotate_secret"])
        want = r.get("config_version")
        if isinstance(want, int):
            self.wanted_version = want
        if r.get("agent_update"):
            self.update(r["agent_update"])
        if first:
            log.info(_("Conectado con el portal (config v{version}, jobs pendientes {jobs})", version=want, jobs=r.get('pending_jobs', 0)))

    def maybe_apply(self):
        want = self.wanted_version
        if want is None or self.disabled:
            return
        if want == self.applied_version() and not self.apply_error:
            return
        if self.apply_error and time.monotonic() - self.apply_failed_at < APPLY_RETRY_SEC:
            return
        try:
            self.sync_config()
        except PortalError as e:
            log.warning(_("No se pudo descargar la configuración: {err}", err=e))

    def rotate_secret(self, new):
        new = (new or "").strip()
        if not re.match(r"^[A-Za-z0-9_]{16,128}$", new) or new == self.portal.secret():
            return
        atomic_write(self.s["secret_file"], new + "\n", 0o600)
        log.info(_("Secreto rotado; el portal lo confirmará con la próxima petición"))

    # ---- actualización
    def update(self, u):
        ver, sha, url = str(u.get("version", "")), str(u.get("sha256", "")).lower(), str(u.get("url", ""))
        if not re.fullmatch(r"\d+\.\d+\.\d+", ver) or not re.fullmatch(r"[0-9a-f]{64}", sha) or url != API_PREFIX + "/agent":
            return
        if tuple(map(int, ver.split("."))) <= tuple(map(int, AGENT_VERSION.split("."))):
            return
        if time.monotonic() - self.update_failed.get((ver, sha), -1e9) < 3600 or self.jobs:
            return
        log.info(_("Actualizando el agente {old} → {new}", old=AGENT_VERSION, new=ver))
        try:
            content, _hdrs = self.portal.request("GET", url, raw=True, timeout=60)
            problem = None
            if hashlib.sha256(content).hexdigest() != sha:
                problem = _("SHA-256 no coincide")
            else:
                text = content.decode("utf-8")
                if not re.search(rf'^AGENT_VERSION\s*=\s*["\']{re.escape(ver)}["\']\s*$', text, re.M):
                    problem = _("el fichero no declara la versión anunciada")
                else:
                    compile(text, "netkido-agent.py", "exec")
            if problem:
                raise RuntimeError(problem)
            me = os.path.realpath(__file__)
            shutil.copy2(me, me + ".prev")
            atomic_write(me, text, 0o755)
        except Exception as e:
            log.error(_("Actualización a {new} fallida: {err}", new=ver, err=e))
            self.update_failed[(ver, sha)] = time.monotonic()
            return
        self.event("agent_updated", f"{AGENT_VERSION} → {ver}")
        log.info(_("Agente actualizado; reiniciando"))
        os.execv(sys.executable, [sys.executable, os.path.realpath(__file__)] + sys.argv[1:])

    # ---- jobs
    def poll_jobs(self):
        try:
            data = self.portal.get("/jobs")
        except PortalError as e:
            if e.status not in (403, 429):
                log.warning(f"Jobs: {e}")
            return False
        for job in data.get("jobs", []):
            if not self.job_sem.acquire(blocking=False):
                log.warning(_("Job {id} no se ejecuta: límite de {max} simultáneos", id=job.get('id'), max=MAX_CONCURRENT_JOBS))
                self._report(job.get("id"), 75, "", _("La sede tenía demasiados jobs en curso."))
                continue
            t = threading.Thread(target=self.run_job, args=(job,), daemon=True)
            self.jobs[job["id"]] = t
            t.start()
        return bool(data.get("jobs"))

    def _report(self, job_id, code, out, err):
        try:
            self.portal.post(f"/jobs/{job_id}/result", {"exit_code": code, "output": out, "error": err})
        except PortalError as e:
            log.error(_("[{id}] no se pudo enviar el resultado: {err}", id=job_id, err=e))

    def run_job(self, job):
        jid, label = job["id"], job.get("label", job["id"])
        timeout = max(5, min(int(job.get("timeout", 60)), MAX_JOB_TIMEOUT))
        script = job.get("script", {})
        code, out, err, tmp = -1, "", "", None
        try:
            self.portal.post(f"/jobs/{jid}/start")
            interp = {"bash": "bash", "python3": "python3"}.get(script.get("type"))
            if not interp or not shutil.which(interp):
                raise FileNotFoundError(_("intérprete no disponible: {type}", type=script.get('type')))
            fd, tmp = tempfile.mkstemp(prefix="nk-job-", suffix=".sh" if interp == "bash" else ".py")
            with os.fdopen(fd, "w") as f:
                f.write(script.get("body", ""))
            os.chmod(tmp, 0o700)
            env = {k: v for k, v in os.environ.items() if not k.startswith("NETKIDO_SECRET")}
            env.update({"NETKIDO_JOB_ID": jid, "NETKIDO_NODE_ID": self.portal.node_id,
                        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
            log.info(f"[{jid}] {label}")
            # Grupo de procesos propio: al agotar el tiempo se mata el script y todo lo que haya
            # lanzado (si un nieto se quedara con stdout abierto, communicate() no volvería nunca).
            p = subprocess.Popen([shutil.which(interp), tmp] + [str(a) for a in script.get("args", [])],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                 text=True, errors="replace", env=env, cwd="/tmp", start_new_session=True)
            try:
                out, err = p.communicate(timeout=timeout)
                code = p.returncode
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    out, err = p.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    out, err = "", ""
                code, err = 124, (err or "") + f"\nTiempo agotado ({timeout} s)"
        except FileNotFoundError as e:
            code, err = 127, str(e)
        except Exception as e:
            code, err = 1, f"{type(e).__name__}: {e}"
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
            self._report(jid, code, truncate(out, MAX_OUTPUT_BYTES), truncate(err, 65536))
            self.jobs.pop(jid, None)
            self.job_sem.release()
            log.info(_("[{id}] terminado con código {code}", id=jid, code=code))

    # ---- bucles
    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop.set())
        log.info(_("Netkido agent {version} · sede {node} · {portal}", version=AGENT_VERSION, node=self.portal.node_id, portal=self.portal.base))
        self.heartbeat(first=True)
        self.event("agent_started", f"agente {AGENT_VERSION}")
        threading.Thread(target=self._jobs_loop, daemon=True).start()
        next_hb = time.monotonic() + HEARTBEAT_SEC
        while not self.stop.is_set():
            self.maybe_apply()
            if time.monotonic() >= next_hb:
                self.heartbeat()
                next_hb = time.monotonic() + (300 if self.disabled else HEARTBEAT_SEC)
            self.stop.wait(5)
        log.info(_("Deteniendo; esperando a los jobs en curso"))
        for t in list(self.jobs.values()):
            t.join(timeout=30)


    def _jobs_loop(self):
        idle = 0
        while not self.stop.is_set():
            if self.disabled:
                self.stop.wait(300)
                continue
            if self.poll_jobs():
                idle = 0
                self.stop.wait(POLL_FAST_SEC)
            else:
                idle += 1
                self.stop.wait(min(POLL_MAX_SEC, POLL_FAST_SEC * (2 ** min(idle, 3))))


def truncate(text, limit):
    b = (text or "").encode("utf-8", errors="replace")
    return text if len(b) <= limit else b[:limit].decode("utf-8", errors="ignore") + "\n[TRUNCADO]"


def os_pretty():
    for line in (read("/etc/os-release", "") or "").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip('"')
    return platform.platform()


# ─── Comandos ────────────────────────────────────────────────────────────────

def ensure_wg_key(path):
    key = (read(path, "") or "").strip()
    if not key:
        key = sh(["wg", "genkey"]).stdout.strip()
        atomic_write(path, key + "\n", 0o600)
    return sh(["wg", "pubkey"], input_text=key + "\n").stdout.strip()


def cmd_enroll(args):
    s = load_settings()
    s["portal"] = args.portal.rstrip("/")
    s["tls_verify"] = not args.insecure
    if args.lang:
        s["lang"] = args.lang
        set_lang(args.lang)
    os.makedirs(CONF_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)
    pub = ensure_wg_key(s["wg_key_file"])
    m = Metrics("nk0")
    portal = Portal(s)
    try:
        r = portal.post("/enroll", {
            "token": args.token,
            "wg_public_key": pub,
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()} · {os_pretty()}",
            "agent_version": AGENT_VERSION,
            "bgp_md5": tcp_md5_supported(),
            "interfaces": m.interfaces(),
        }, signed=False)
    except PortalError as e:
        log.error(_("Inscripción rechazada: {err}", err=e))
        return 1
    s["node_id"] = r["node_id"]
    atomic_write(s["secret_file"], r["secret"] + "\n", 0o600)
    save_settings(s)
    log.info(_("Sede inscrita: {node}", node=r['node_id']))
    agent = Agent(s)
    return 0 if agent.apply_config(r["config"]) else 2


def cmd_apply(args):
    s = load_settings()
    agent = Agent(s)
    if args.cached:
        cfg = agent.cached_config()
        if not cfg:
            log.error(_("No hay configuración guardada"))
            return 1
    else:
        try:
            cfg = Portal(s).get("/config")
        except PortalError as e:
            log.warning(_("{err}; se aplica la configuración guardada", err=e))
            cfg = agent.cached_config()
            if not cfg:
                return 1
    return 0 if agent.apply_config(cfg) else 2


def cmd_run(_args):
    s = load_settings()
    if not s.get("portal") or not s.get("node_id"):
        log.error(_("Sede sin inscribir ({path}). Usa el comando de instalación del panel.", path=AGENT_CONF))
        return 1
    Agent(s).run()
    return 0


def cmd_status(_args):
    s = load_settings()
    cfg = Agent.cached_config() or {}
    print(json.dumps({
        "agent_version": AGENT_VERSION,
        "portal": s.get("portal"),
        "node_id": s.get("node_id"),
        "applied_config_version": Agent.applied_version(),
        "vrf": cfg.get("overlay", {}).get("vrf"),
        "lan": cfg.get("lan", {}).get("address"),
        "underlay": cfg.get("wireguard", {}).get("address"),
    }, indent=2))
    return 0


def main():
    set_lang(os.environ.get("NETKIDO_LANG") or load_settings().get("lang"))
    ap = argparse.ArgumentParser(prog="netkido-agent", description=_("Agente de sede Netkido"))
    ap.add_argument("--log-level", default=os.environ.get("NETKIDO_LOG_LEVEL", "INFO"),
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll", help=_("inscribir la sede con un token de instalación"))
    e.add_argument("--portal", required=True)
    e.add_argument("--token", required=True)
    e.add_argument("--insecure", action="store_true", help=_("no verificar TLS (solo laboratorio)"))
    e.add_argument("--lang", choices=sorted(LANGS), help=_("idioma de los mensajes del agente"))
    a = sub.add_parser("apply", help=_("aplicar la configuración"))
    a.add_argument("--cached", action="store_true", help=_("usar la última guardada sin preguntar al portal"))
    sub.add_parser("run", help=_("ejecutar el agente"))
    sub.add_parser("status", help=_("estado local"))
    args = ap.parse_args()
    setup_logging(load_settings().get("log_file") if args.cmd == "run" else None, args.log_level)
    if os.geteuid() != 0 and args.cmd != "status":
        log.error(_("El agente tiene que ejecutarse como root"))
        return 1
    return {"enroll": cmd_enroll, "apply": cmd_apply, "run": cmd_run, "status": cmd_status}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
