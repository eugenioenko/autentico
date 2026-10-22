import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser(
    description="Exercise migration through Docker Compose with a mounted database."
)
parser.add_argument("--binary", required=True, type=Path)
parser.add_argument("--runtime-image", default="debian:bookworm-slim")
target_schema = 19
args = parser.parse_args()
if os.getuid() == 0:
    parser.error(
        "Run as a non-root host user to verify service startup after a root migration."
    )
root = Path(__file__).resolve().parents[2]
temp = Path(tempfile.mkdtemp(prefix="autentico-445-container-"))
data = temp / "data"
data.mkdir()
dbpath = data / "autentico.db"
db = sqlite3.connect(dbpath)
for v in range(1, 15):
    file = next((root / "pkg/db/migrations").glob(f"{v:03d}_*.go"))
    sql = re.search(r"const migration\d+ = `([\s\S]*?)`", file.read_text()).group(1)
    db.executescript(sql)
    db.execute(f"PRAGMA user_version={v}")
db.executescript(
    "INSERT INTO users(id,username,password,totp_secret,totp_verified) VALUES('u','kept-user','kept-password','JBSWY3DPEHPK3PXP',1); INSERT INTO tokens(id,user_id,access_token,refresh_token,access_token_type,refresh_token_expires_at,access_token_expires_at,scope,grant_type) VALUES('t','u','old-access','old-refresh','Bearer',datetime('now','+1 day'),datetime('now','+1 hour'),'openid','password'); INSERT INTO sessions(id,user_id,access_token,refresh_token) VALUES('s','u','old-access','old-refresh'); CREATE TRIGGER fail_migration BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT,'injected container failure'); END;"
)
db.close()
config = {
    "services": {
        "autentico": {
            "image": args.runtime_image,
            "entrypoint": ["autentico"],
            "command": ["start"],
            "working_dir": "/app/data",
            "volumes": [
                str(data) + ":/app/data",
                str(args.binary.resolve()) + ":/usr/local/bin/autentico:ro",
            ],
            "ports": ["127.0.0.1:0:9999"],
            "environment": {
                "AUTENTICO_DB_FILE_PATH": "/app/data/autentico.db",
                "AUTENTICO_APP_URL": "http://localhost:9999",
                "AUTENTICO_ACCESS_TOKEN_SECRET": "container-test-access",
                "AUTENTICO_REFRESH_TOKEN_SECRET": "container-test-refresh",
                "AUTENTICO_CSRF_SECRET_KEY": "01234567890123456789012345678901",
            },
        }
    }
}
# Model an existing service-owned v2 configuration, upgraded by a root CLI.
envpath = data / ".env"
original_env = "# existing configuration\nAUTENTICO_REFRESH_TOKEN_SECRET=container-test-refresh\n"
envpath.write_text(original_env)
envpath.chmod(0o600)
compose = temp / "compose.json"
compose.write_text(json.dumps(config))
base = [
    "docker",
    "compose",
    "-p",
    "autentico-migration-" + str(os.getpid()),
    "-f",
    str(compose),
]


def call(args, success=True, contains=None):
    r = subprocess.run(
        base + args,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        stdin=subprocess.DEVNULL,
    )
    if success and r.returncode:
        raise RuntimeError(r.stdout)
    if not success and not r.returncode:
        raise RuntimeError("unexpected success: " + r.stdout)
    if contains and contains not in r.stdout:
        raise RuntimeError(r.stdout)
    return r.stdout


try:
    before = dbpath.read_bytes()
    call(["run", "--rm", "-T", "autentico", "migrate", "--approve-major=15,17"], False, "AUTENTICO_TOTP_ENCRYPTION_KEY is required")
    assert dbpath.read_bytes() == before
    assert not list(data.glob("*.pre-v17-*.db"))
    print("Docker migration refuses missing key without changing the database", flush=True)
    call(["run", "--rm", "-T", "autentico", "init"], True, "other settings and keys were preserved")
    after_init = envpath.read_bytes()
    assert after_init.startswith(original_env.encode())
    assert envpath.stat().st_uid == os.getuid(), "init changed existing config owner"
    call(["run", "--rm", "-T", "--user", f"{os.getuid()}:{os.getgid()}", "autentico", "init"], True, "no changes made")
    assert envpath.read_bytes() == after_init
    print("Docker init adds the key once and preserves config ownership and secrets", flush=True)
    groupdir = data / "group-config"
    groupdir.mkdir()
    groupenv = groupdir / ".env"
    groupenv.write_text(original_env)
    container_groupenv = "/app/data/group-config/.env"
    call(["run", "--rm", "-T", "--entrypoint", "chown", "autentico", f"0:{os.getgid()}", container_groupenv])
    call(["run", "--rm", "-T", "--entrypoint", "chmod", "autentico", "0640", container_groupenv])
    call(["run", "--rm", "-T", "autentico", "init", "--output", "/app/data/group-config"], True, "other settings and keys were preserved")
    assert groupenv.stat().st_uid == 0 and groupenv.stat().st_gid == os.getgid()
    assert groupenv.stat().st_mode & 0o777 == 0o640
    assert groupenv.read_text().startswith(original_env)
    call(["run", "--rm", "-T", "--user", f"{os.getuid()}:{os.getgid()}",
          "--workdir", "/app/data/group-config", "-e", "AUTENTICO_DB_FILE_PATH=/app/data/group-config/read-check.db",
          "autentico", "onboard", "--username", "group-read-check", "--password", "Password123!", "--email", "group@test.com"], True, "Onboarding complete")
    print("Docker root:service 0640 config remains readable by the service after key addition", flush=True)
    call(
        ["run", "--rm", "-T", "autentico", "start"],
        False,
        "automatic upgrade is disabled",
    )
    print("Docker startup refuses major upgrade", flush=True)
    call(["run", "--rm", "-T", "autentico", "migrate"], False, "failed to read input")
    print("Docker headless migration requires approval", flush=True)
    call(
        ["run", "--rm", "-T", "autentico", "migrate", "--approve-major=15,17"],
        False,
        "restored schema v14",
    )
    assert dbpath.stat().st_uid == os.getuid(), "restoration changed database owner"
    db = sqlite3.connect(dbpath)
    assert db.execute("PRAGMA user_version").fetchone()[0] == 14
    assert db.execute("SELECT access_token FROM tokens").fetchone()[0] == "old-access"
    db.execute("DROP TRIGGER fail_migration")
    db.commit()
    db.close()
    print("Docker failed migration restores schema and credentials", flush=True)
    call(
        ["run", "--rm", "-T", "autentico", "migrate", "--approve-major=15,17"],
        True,
        "Migration v15 applied",
    )
    db = sqlite3.connect(dbpath)
    assert db.execute("PRAGMA user_version").fetchone()[0] == target_schema
    assert db.execute("SELECT count(*) FROM federation_login_flows").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_federation_login_flows_expiry'").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM tokens").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0
    assert db.execute("SELECT username FROM users").fetchone()[0] == "kept-user"
    stored, verified = db.execute("SELECT totp_secret,totp_verified FROM users WHERE id='u'").fetchone()
    assert stored.startswith("totp:v1:") and "JBSWY3DPEHPK3PXP" not in stored
    assert verified == 1
    db.close()
    print("Docker approved retry purges old sessions and preserves encrypted TOTP enrollment", flush=True)
    # Privileged migration must leave the persistent lock usable by the service.
    service_user = f"{os.getuid()}:{os.getgid()}"
    lockpath = Path(str(dbpath) + ".lock")
    assert lockpath.stat().st_uid == os.getuid(), "migration changed lock owner"
    call(
        [
            "run",
            "--rm",
            "-T",
            "--user",
            service_user,
            "autentico",
            "migrate",
            "--approve-major=15,17",
        ],
        True,
        "Already up to date",
    )
    config["services"]["autentico"]["user"] = service_user
    compose.write_text(json.dumps(config))
    call(["up", "-d", "autentico"])
    address = call(["port", "autentico", "9999"]).strip()
    deadline = time.time() + 20
    while True:
        try:
            with urllib.request.urlopen(
                "http://" + address + "/.well-known/openid-configuration", timeout=1
            ) as response:
                assert response.status == 200
            break
        except Exception:
            if time.time() > deadline:
                raise
            time.sleep(0.1)
    print(
        "Docker service user starts after root migration using the same lock",
        flush=True,
    )
    call(
        ["run", "--rm", "-T", "autentico", "migrate", "--approve-major=15,17"],
        True,
        "Already up to date",
    )
    print("Docker deployment job retries safely", flush=True)
finally:
    subprocess.run(
        base + ["down", "--volumes", "--remove-orphans"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    shutil.rmtree(temp)
