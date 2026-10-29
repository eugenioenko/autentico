#!/usr/bin/env python3
"""Black-box fixture: real Autentico, TLS proxies and an instrumented HTTP app.

Linux Docker host networking is intentional: no host files, external DNS,
production data, public ports, or application-internal test backdoors are used.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]
ADMIN = "http://127.0.0.1:25998"
AUTH = "https://auth.example.test:25443"
IMAGES = {"caddy": "caddy:2.10.2", "nginx": "nginx:1.28.0", "traefik": "traefik:v3.5.0"}


def request(path, body=None, token=None, method=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    with urllib.request.urlopen(urllib.request.Request(ADMIN + path, data, headers, method=method), timeout=10) as response:
        content = response.read()
        return json.loads(content) if content else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--logs", type=Path)
    parser.add_argument("--site-mode", choices=("same-site", "cross-site"), default="same-site")
    args = parser.parse_args()
    binary = args.binary.resolve()
    directory = Path(tempfile.mkdtemp(prefix="autentico-forwardauth-"))
    containers = []
    server = None
    server_lock = threading.Lock()
    logs = []
    servers = []
    run_id = secrets.token_hex(5)
    env = dict(os.environ, AUTENTICO_DB_FILE_PATH=str(directory / "identity.db"), AUTENTICO_LISTEN_PORT="25998",
               AUTENTICO_TRUSTED_PROXIES="127.0.0.1/32", AUTENTICO_RATE_LIMIT_RPS="0", AUTENTICO_RATE_LIMIT_RPM="0",
               AUTENTICO_ANTI_TIMING_MIN_MS="0", AUTENTICO_ANTI_TIMING_MAX_MS="0")
    status = 1
    try:
        def command(*cmd):
            subprocess.run(cmd, cwd=directory, env=env, check=True, stdout=subprocess.DEVNULL)
        command(str(binary), "init", "--url", AUTH)
        command(str(binary), "onboard", "--username", "admin", "--password", "Password123!", "--email", "admin@test.com", "--enable-admin-password-grant")

        def stop_auth():
            nonlocal server
            with server_lock:
                if server and server.poll() is None:
                    server.terminate()
                    try:
                        server.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()
                server = None

        def start_auth():
            nonlocal server
            with server_lock:
                if server and server.poll() is None:
                    return
                log = open(directory / "autentico.log", "a")
                logs.append(log)
                server = subprocess.Popen([str(binary), "start"], cwd=directory, env=env, stdout=log, stderr=log)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                try:
                    request("/healthz")
                    return
                except Exception:
                    if server.poll() is not None:
                        raise RuntimeError((directory / "autentico.log").read_text())
                    time.sleep(.1)
            raise RuntimeError("Autentico did not start")

        start_auth()
        form = urllib.parse.urlencode(dict(grant_type="password", client_id="autentico-admin", username="admin", password="Password123!", scope="openid profile email"))
        with urllib.request.urlopen(urllib.request.Request(ADMIN + "/oauth2/token", form.encode(), {"Content-Type": "application/x-www-form-urlencoded"})) as response:
            admin_token = json.load(response)["access_token"]
        request("/admin/api/settings", {"sso_enabled": "true", "require_mfa": "false", "sso_session_max_age": "24h"}, admin_token, "PUT")
        user = request("/admin/api/users", {"username": "proxy-user", "password": "Password123!", "email": "proxy@test.com"}, admin_token)["data"]
        request("/admin/api/users/" + user["id"], {"is_email_verified": True}, admin_token, "PUT")
        apps = {}
        for name, port in (("caddy", 25443), ("nginx", 25444), ("traefik", 25445)):
            host = f"{name}.{name}-app.test" if args.site_mode == "cross-site" else f"{name}.example.test"
            apps[name] = request("/admin/api/protected-apps", {"name": name, "origin": f"https://{host}:{port}", "allowed_return_paths": ["/"], "session_ttl": "8h"}, admin_token)["data"]
        control_key = secrets.token_hex(32)
        hits = []

        class Backend(BaseHTTPRequestHandler):
            def do_GET(self):
                self.respond()

            def do_POST(self):
                self.respond()

            def respond(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
                payload = dict(path=self.path, method=self.command, headers=dict(self.headers), body=body)
                hits.append(payload)
                encoded = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_):
                pass

        class Control(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.headers.get("Authorization") != "Bearer " + control_key:
                    self.send_error(403)
                    return
                if self.path == "/stop-auth":
                    stop_auth()
                elif self.path == "/start-auth":
                    start_auth()
                elif self.path == "/relocate-auth":
                    stop_auth()
                    env["AUTENTICO_APP_URL"] = "https://auth.other.test:25443"
                    start_auth()
                elif self.path == "/collide-auth":
                    stop_auth()
                    env["AUTENTICO_APP_URL"] = apps["caddy"]["origin"]
                    start_auth()
                elif self.path == "/restore-auth":
                    stop_auth()
                    env.pop("AUTENTICO_APP_URL", None)
                    start_auth()
                elif self.path == "/stats":
                    pass
                else:
                    self.send_error(404)
                    return
                data = json.dumps({"hits": len(hits)}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_):
                pass

        for port, handler in ((25999, Backend), (25997, Control)):
            httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
            servers.append(httpd)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
        domains = ("example.test", "other.test", "caddy-app.test", "nginx-app.test", "traefik-app.test")
        names = ",".join("DNS:*." + domain for domain in domains)
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", str(directory / "key.pem"), "-out", str(directory / "cert.pem"), "-subj", "/CN=*.example.test", "-addext", "subjectAltName=" + names)
        (directory / "key.pem").chmod(0o644)
        for name, filename in (("caddy", "Caddyfile"), ("nginx", "nginx.conf"), ("traefik", "traefik.yml")):
            config = (ROOT / "tests/proxy/configs" / filename).read_text().replace(name.upper() + "_APP_ID", apps[name]["id"])
            config = config.replace(f"{name}.example.test", urllib.parse.urlsplit(apps[name]["origin"]).hostname)
            if name == "caddy":
                # Empty first-party/sibling pages for real browser attack and
                # third-party-cookie tests, without an application auth bypass.
                hosts = ", ".join(f"https://evil.{domain}:25443" for domain in domains)
                config += f"\n{hosts} {{\n    tls /certs/cert.pem /certs/key.pem\n    respond `Test browser origin`\n}}\n"
            (directory / filename).write_text(config)
            container = "autentico-fa-" + name + "-" + run_id
            containers.append(container)
            flags = []
            if name == "caddy":
                flags = ["caddy", "run", "--config", "/certs/Caddyfile", "--adapter", "caddyfile"]
            elif name == "nginx":
                flags = ["nginx", "-c", "/certs/nginx.conf", "-g", "daemon off;"]
            else:
                flags = ["--entrypoints.websecure.address=127.0.0.1:25445", "--providers.file.filename=/certs/traefik.yml", "--log.level=ERROR"]
            subprocess.run(["docker", "run", "--detach", "--name", container, "--network", "host", "--mount", f"type=bind,src={directory},dst=/certs,readonly", IMAGES[name], *flags], check=True, stdout=subprocess.DEVNULL)
        import socket
        for port in (25443, 25444, 25445, 25446):
            deadline = time.monotonic() + 30
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        pass
                    break
                except Exception:
                    if time.monotonic() > deadline:
                        raise RuntimeError(f"Proxy on port {port} did not start")
                    time.sleep(.1)
        fixture = dict(admin=ADMIN, auth=AUTH, authNginx="https://auth.example.test:25446", token=admin_token, user=user, apps=apps, crossDomain=args.site_mode == "cross-site", control="http://127.0.0.1:25997", controlKey=control_key)
        (directory / "fixture.json").write_text(json.dumps(fixture))
        test_env = dict(os.environ, AUTENTICO_PROXY_FIXTURE=str(directory / "fixture.json"))
        status = subprocess.run([str(ROOT / "tests/browser/node_modules/.bin/playwright"), "test", "--config", "proxy.config.ts"], cwd=ROOT / "tests/browser", env=test_env).returncode
    finally:
        if server and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
        for httpd in servers:
            httpd.shutdown()
            httpd.server_close()
        for container in containers:
            log = subprocess.run(["docker", "logs", container], capture_output=True, text=True)
            (directory / (container.split("-")[2] + ".log")).write_text(log.stdout + log.stderr)
            subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for log in logs:
            log.close()
        if args.logs:
            args.logs.mkdir(parents=True, exist_ok=True)
            for log in directory.glob("*.log"):
                shutil.copy(log, args.logs / log.name)
        if status:
            print("Proxy fixture failed; diagnostic files retained in", directory)
            for log in directory.glob("*.log"):
                print(log.name, log.read_text()[-6000:])
        else:
            shutil.rmtree(directory)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
