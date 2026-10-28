# SPDX-License-Identifier: AGPL-3.0-only
"""
Pruebas del servidor (server/netkido) con el agente real (node/netkido-agent.py) como cliente y
netkido-hub-apply --check. No necesitan root ni tocan la red del sistema.

    python3 -m unittest discover -s tests -v
"""
import base64
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def wg_key(seed):
    return base64.b64encode(hashlib.sha256(seed.encode()).digest()).decode()


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="nk-test-")
        lib = os.path.join(cls.tmp, "lib")
        os.makedirs(lib)
        for f in ("node/netkido-agent.py", "node/install.sh", "server/messages.json"):
            shutil.copy(os.path.join(ROOT, f), lib)
        # netkido-hub-apply de verdad, pero solo validando (--check): sin root ni cambios en el sistema.
        cls.hub_log = os.path.join(cls.tmp, "hub.log")
        hub = os.path.join(cls.tmp, "hub-apply")
        with open(hub, "w") as f:
            f.write(f"#!/bin/sh\ncat > {cls.tmp}/hub-state.json\n"
                    f"{sys.executable} {ROOT}/hub/netkido-hub-apply --check --from {cls.tmp}/hub-state.json >> {cls.hub_log} 2>&1\n")
        os.chmod(hub, 0o755)
        os.environ.update(NETKIDO_STATE_DIR=os.path.join(cls.tmp, "state"), NETKIDO_LIB_DIR=lib, NETKIDO_HUB_APPLY=hub)
        os.makedirs(os.environ["NETKIDO_STATE_DIR"])
        cls.nk = load("netkido_server", os.path.join(ROOT, "server/netkido"))
        cls.nk.os.geteuid = lambda: 0          # el comando exige root; aquí no hace falta
        os.environ["NETKIDO_CONF_DIR"] = os.path.join(cls.tmp, "agent")
        os.environ["NETKIDO_STATE_DIR_AGENT"] = os.path.join(cls.tmp, "agent-state")
        cls.agent = load("netkido_agent", os.path.join(ROOT, "node/netkido-agent.py"))
        with open(cls.nk.STATE_FILE, "w") as f:
            json.dump(cls.nk.new_state("vpn.example.com", "vpn.example.com:51820", wg_key("hub"), ["1.1.1.1"]), f)
        # Servidor HTTP (sin TLS) en un puerto libre.
        cls.nk.Handler.api = cls.nk.Api(cls.nk.State(), "http://127.0.0.1")
        cls.httpd = cls.nk.Server(("127.0.0.1", 0), cls.nk.Handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.nk.Handler.api.base_url = cls.base
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def cli(self, *args):
        from io import StringIO
        from contextlib import redirect_stdout, redirect_stderr
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.nk.main(list(args))
        return code, out.getvalue() + err.getvalue()

    def token_of(self, output):
        import re
        return re.search(r"/install/([A-Za-z0-9]{40})", output).group(1)

    def portal(self, node_id="", secret=""):
        secret_file = os.path.join(self.tmp, "secret-" + hashlib.sha256(f"{node_id}:{secret}".encode()).hexdigest()[:12])
        with open(secret_file, "w") as f:
            f.write(secret)
        return self.agent.Portal({"portal": self.base, "node_id": node_id, "secret_file": secret_file})

    def enroll(self, name, lan, seed):
        code, out = self.cli("site", "add", name, lan, "--ports", "eth1")
        self.assertEqual(code, 0, out)
        token = self.token_of(out)
        r = self.portal().post("/enroll", {"token": token, "wg_public_key": wg_key(seed), "hostname": "cpe",
                                           "os": "Linux · Debian 12", "agent_version": "1.0.0", "bgp_md5": True}, signed=False)
        return token, r

    def test_1_sites_validation(self):
        code, out = self.cli("site", "add", "Madrid", "8.8.8.1/24")
        self.assertNotEqual(code, 0)
        self.assertIn("privada", out)
        code, out = self.cli("site", "add", "Getafe", "10.20.0.1/16")
        self.assertEqual(code, 0, out)
        code, out = self.cli("site", "add", "Leganés", "10.20.5.1/24")
        self.assertIn("se solapa", out)
        code, out = self.cli("site", "add", "Túnel", "100.64.3.1/24")
        self.assertNotEqual(code, 0)
        code, out = self.cli("site", "list")
        self.assertIn("pendiente de instalar", out)
        self.assertEqual(self.cli("site", "remove", "getafe")[0], 0)

    def test_2_install_enroll_heartbeat_config(self):
        token, r = self.enroll("Oficina Madrid", "192.168.10.1/24", "madrid")
        nid, secret, cfg = r["node_id"], r["secret"], r["config"]
        # La configuración la acepta el agente y el hub la valida.
        self.agent.validate_config(cfg)
        self.assertEqual(cfg["lan"]["interfaces"], ["eth1"])
        self.assertEqual(cfg["lan"]["dhcp"]["start"], "192.168.10.128")
        self.assertEqual(cfg["overlay"]["vrf"], "TENANT-1")
        self.assertNotIn("ids", cfg)
        hub = json.load(open(os.path.join(self.tmp, "hub-state.json")))
        self.assertEqual(hub["tenants"][0]["nodes"][0]["lan"], "192.168.10.0/24")
        self.assertIn("neighbor 100.64.0.", open(self.hub_log).read())
        # El enlace ya no vale.
        import urllib.request
        body = urllib.request.urlopen(f"{self.base}/install/{token}").read().decode()
        self.assertIn("no es válido", body)
        with self.assertRaises(self.agent.PortalError):
            self.portal().post("/enroll", {"token": token, "wg_public_key": wg_key("otra")}, signed=False)

        p = self.portal(nid, secret)
        hb = p.post("/heartbeat", {"agent_version": "1.0.0", "applied_config_version": cfg["version"], "bgp_md5": True})
        self.assertEqual(hb["config_version"], cfg["version"])
        self.assertIn("agent_update", hb, "agente más antiguo que el del servidor")
        self.assertEqual(p.get("/config")["version"], cfg["version"])
        self.assertEqual(p.get("/jobs"), {"jobs": []})
        # Kernel sin TCP MD5: configuración nueva sin contraseña BGP.
        import time
        time.sleep(self.nk.HEARTBEAT_MIN + 0.1)
        hb = p.post("/heartbeat", {"agent_version": "1.0.0", "bgp_md5": False})
        self.assertEqual(hb["config_version"], cfg["version"] + 1)
        self.assertIsNone(p.get("/config")["bgp"]["password"])
        # Firma mala o secreto de otra sede: 401. Desactivada: 403.
        with self.assertRaises(self.agent.PortalError) as e:
            self.portal(nid, "otro-secreto").get("/config")
        self.assertEqual(e.exception.status, 401)
        self.assertEqual(self.cli("site", "disable", "oficina-madrid")[0], 0)
        with self.assertRaises(self.agent.PortalError) as e:
            p.get("/config")
        self.assertEqual(e.exception.status, 403)
        hub = json.load(open(os.path.join(self.tmp, "hub-state.json")))
        self.assertEqual(hub["tenants"], [], "sin sedes activas")
        self.assertEqual(self.cli("site", "enable", "oficina-madrid")[0], 0)

    def test_3_installer_and_agent_download(self):
        code, out = self.cli("site", "add", "Tienda Sol", "192.168.30.1/24")
        token = self.token_of(out)
        import urllib.request
        script = urllib.request.urlopen(f"{self.base}/install/{token}?lang=en").read().decode()
        self.assertIn(f'TOKEN="{token}"', script)
        self.assertIn(f'PORTAL="{self.base}"', script)
        self.assertIn("M_DONE=' Site installed.", script)
        self.assertNotIn("@@", script)
        self.assertEqual(subprocess.run(["bash", "-n"], input=script, text=True).returncode, 0)
        r = urllib.request.urlopen(f"{self.base}/install/{token}/agent")
        data = r.read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), r.headers["X-Netkido-Agent-Sha256"])

    def test_4_replayed_request_is_rejected(self):
        _t, r = self.enroll("Almacén", "192.168.40.1/24", "almacen")
        import time
        import urllib.request
        p = self.portal(r["node_id"], r["secret"])
        headers = p._sign("GET", "/api/agent/v1/config", b"")
        req = lambda: urllib.request.urlopen(urllib.request.Request(f"{self.base}/api/agent/v1/config", headers=headers))
        self.assertEqual(req().status, 200)
        with self.assertRaises(urllib.error.HTTPError) as e:
            req()
        self.assertEqual(e.exception.code, 401)


if __name__ == "__main__":
    unittest.main()
