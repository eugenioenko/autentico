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
target_schema = 16
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
    "INSERT INTO users(id,username,password) VALUES('u','kept-user','kept-password'); INSERT INTO tokens(id,user_id,access_token,refresh_token,access_token_type,refresh_token_expires_at,access_token_expires_at,scope,grant_type) VALUES('t','u','old-access','old-refresh','Bearer',datetime('now','+1 day'),datetime('now','+1 hour'),'openid','password'); INSERT INTO sessions(id,user_id,access_token,refresh_token) VALUES('s','u','old-access','old-refresh'); CREATE TRIGGER fail_migration BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT,'injected container failure'); END;"
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
    call(
        ["run", "--rm", "-T", "autentico", "start"],
        False,
        "automatic upgrade is disabled",
    )
    print("Docker startup refuses major upgrade", flush=True)
    call(["run", "--rm", "-T", "autentico", "migrate"], False, "failed to read input")
    print("Docker headless migration requires approval", flush=True)
    call(
        ["run", "--rm", "-T", "autentico", "migrate", "--approve-major=15"],
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
        ["run", "--rm", "-T", "autentico", "migrate", "--approve-major=15"],
        True,
        "Migration v15 applied",
    )
    db = sqlite3.connect(dbpath)
    assert db.execute("PRAGMA user_version").fetchone()[0] == target_schema
    assert db.execute("SELECT count(*) FROM tokens").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0
    assert db.execute("SELECT username FROM users").fetchone()[0] == "kept-user"
    db.close()
    print("Docker approved retry purges sessions and preserves account", flush=True)
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
            "--approve-major=15",
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
        ["run", "--rm", "-T", "autentico", "migrate", "--approve-major=15"],
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
