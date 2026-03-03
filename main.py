# main.py
# AwsSsoSsmDashboardTool
# Title: SRC Platform SSO & SSM Control Panel
#
# Desktop UI: pywebview window ONLY (no browser auto-open)
# Flask runs locally in background on 127.0.0.1
# PyInstaller-safe paths for templates/static/schema.sql
# macOS: SSM sessions launched in Terminal.app (interactive)
# Inventory / jumpbox / SSM logic unchanged (only UI wrapper + no browser auto-open)

import os
import sys
import re
import json
import csv
import uuid
import shlex
import threading
import subprocess
import datetime
import sqlite3
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

# --------------------------------------------------------------------------------------
# App config
# --------------------------------------------------------------------------------------

APP_TITLE = "SRC Platform SSO & SSM Control Panel"
APP_DATA_FOLDER_NAME = "AwsSsoSsmDashboardTool"

DEFAULT_REGIONS = [
    "us-east-1", "us-east-2",
    "us-west-1", "us-west-2",
    "eu-west-1", "eu-central-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
]


def resource_path(relative_path: str) -> str:
    """
    PyInstaller-safe resource resolver:
    - Dev mode: relative to this file
    - Bundled: relative to sys._MEIPASS
    """
    base_path = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
    return os.path.join(base_path, relative_path)


def get_app_data_dir(app_name: str = APP_DATA_FOLDER_NAME) -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            base = str(Path.home() / "AppData" / "Local")
        return Path(base) / app_name

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / app_name

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / app_name
    return Path.home() / ".local" / "share" / app_name


def ensure_dirs(*paths: Path) -> None:
    for p in paths:
        p.mkdir(parents=True, exist_ok=True)


APP_DATA_DIR = get_app_data_dir()
LOG_DIR = APP_DATA_DIR / "logs"
EXPORT_DIR_PATH = APP_DATA_DIR / "exports"
ensure_dirs(APP_DATA_DIR, LOG_DIR, EXPORT_DIR_PATH)

DB_PATH = str(APP_DATA_DIR / "catalog.db")
CATALOG_JSON_PATH = str(APP_DATA_DIR / "catalog.json")

# Use resource_path so schema.sql works when packaged as .app
SCHEMA_SQL_PATH = resource_path("schema.sql")

EXPORT_DIR = str(EXPORT_DIR_PATH)
JOB_LOG_PATH = str(LOG_DIR / "jobs.log")

# Use resource_path so templates/static work inside PyInstaller bundle
app = Flask(
    __name__,
    template_folder=resource_path("app/templates"),
    static_folder=resource_path("app/static"),
)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-me")

# --------------------------------------------------------------------------------------
# Helpers: AWS profile parsing
# --------------------------------------------------------------------------------------

def _read_ini(path: str) -> Dict[str, Dict[str, str]]:
    data: Dict[str, Dict[str, str]] = {}
    if not os.path.exists(path):
        return data

    current = None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1].strip()
                data[current] = {}
                continue
            if "=" in line and current:
                k, v = line.split("=", 1)
                data[current][k.strip()] = v.strip()
    return data


def _aws_paths() -> Tuple[str, str]:
    home = os.path.expanduser("~")
    return (os.path.join(home, ".aws", "config"), os.path.join(home, ".aws", "credentials"))


@dataclass
class AwsProfile:
    name: str
    region: str
    environment: str
    auth_type: str
    is_sso: bool
    has_credentials: bool
    sso_start_url: str = ""
    sso_region: str = ""
    role_name: str = ""
    account_id: str = ""
    sso_session: str = ""


def load_profiles() -> List[AwsProfile]:
    config_path, cred_path = _aws_paths()
    cfg_raw = _read_ini(config_path)
    cred_raw = _read_ini(cred_path)

    def normalize_section_to_profile(section: str) -> str:
        s = (section or "").strip()
        if s.lower() == "default":
            return "default"
        if s.lower().startswith("profile "):
            return s[8:].strip()
        return s

    cfg_profiles: Dict[str, Dict[str, str]] = {}
    sso_sessions: Dict[str, Dict[str, str]] = {}

    for section, kv in cfg_raw.items():
        if section.strip().lower().startswith("sso-session "):
            sess_name = section.strip()[len("sso-session "):].strip()
            sso_sessions[sess_name] = kv
            continue
        pname = normalize_section_to_profile(section)
        cfg_profiles[pname] = kv

    cred_profiles: Dict[str, Dict[str, str]] = {k.strip(): v for k, v in cred_raw.items()}
    all_names = sorted(set(cfg_profiles.keys()) | set(cred_profiles.keys()))

    profiles: List[AwsProfile] = []
    for name in all_names:
        ck_cfg = cfg_profiles.get(name, {})
        ck_cred = cred_profiles.get(name, {})

        merged = dict(ck_cred)
        merged.update(ck_cfg)

        region = (merged.get("region") or merged.get("sso_region") or "us-east-1").strip()

        env = "unknown"
        m = re.search(r"\b(dev|qa|stage|stg|preprod|prod|perf|vnv|demo)\b", name, re.IGNORECASE)
        if m:
            raw = m.group(1).lower()
            if raw == "stg":
                raw = "stage"
            if raw == "demo":
                raw = "stage"
            env = raw

        sso_session = (merged.get("sso_session") or "").strip()
        sess_kv = sso_sessions.get(sso_session, {}) if sso_session else {}

        has_any_sso_key = any(k in merged for k in [
            "sso_start_url", "sso_region", "sso_account_id", "sso_role_name", "sso_session"
        ])

        sso_start_url = (merged.get("sso_start_url") or sess_kv.get("sso_start_url") or "").strip()
        sso_region = (merged.get("sso_region") or sess_kv.get("sso_region") or "").strip()

        is_sso = bool(has_any_sso_key or (sso_session and sso_session in sso_sessions))
        has_creds = name in cred_profiles
        auth_type = "SSO" if is_sso else ("Creds" if has_creds else "Chain/Unknown")

        profiles.append(AwsProfile(
            name=name,
            region=region,
            environment=env,
            auth_type=auth_type,
            is_sso=is_sso,
            has_credentials=has_creds,
            sso_start_url=sso_start_url,
            sso_region=sso_region,
            role_name=(merged.get("sso_role_name") or "").strip(),
            account_id=(merged.get("sso_account_id") or "").strip(),
            sso_session=sso_session,
        ))

    return profiles


# --------------------------------------------------------------------------------------
# SQLite
# --------------------------------------------------------------------------------------

def db_conn() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    if os.path.exists(SCHEMA_SQL_PATH):
        with open(SCHEMA_SQL_PATH, "r", encoding="utf-8") as f:
            schema = f.read()
        con = db_conn()
        try:
            con.executescript(schema)
            con.commit()
        finally:
            con.close()


def ensure_tables_exist():
    con = db_conn()
    try:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS UpdateJob (
                JobId TEXT PRIMARY KEY,
                ProfileName TEXT NOT NULL,
                Region TEXT NOT NULL,
                Status TEXT NOT NULL,
                Pid INTEGER NOT NULL DEFAULT 0,
                CreatedAtUtc TEXT NOT NULL,
                LastUpdateUtc TEXT NOT NULL,
                LogText TEXT NOT NULL DEFAULT ''
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS JumpboxPreference (
                ProfileName TEXT NOT NULL,
                Region      TEXT NOT NULL,
                Env         TEXT NOT NULL,
                TargetType  TEXT NOT NULL,
                JumpboxId   TEXT NOT NULL,
                UpdatedAtUtc TEXT NOT NULL,
                PRIMARY KEY (ProfileName, Region, Env, TargetType)
            )
            """
        )
        con.commit()
    finally:
        con.close()


init_db()
ensure_tables_exist()

# --------------------------------------------------------------------------------------
# Jumpbox Preference (DB)
# --------------------------------------------------------------------------------------

def get_jumpbox_preference(profile: str, region: str, env: str, target_type: str) -> Optional[str]:
    ensure_tables_exist()
    con = db_conn()
    try:
        row = con.execute(
            """
            SELECT JumpboxId FROM JumpboxPreference
            WHERE ProfileName=? AND Region=? AND Env=? AND TargetType=?
            """,
            (profile, region, (env or "OTHER").upper(), (target_type or "db").lower()),
        ).fetchone()
        return row["JumpboxId"] if row else None
    finally:
        con.close()


def set_jumpbox_preference(profile: str, region: str, env: str, target_type: str, jumpbox_id: str) -> None:
    ensure_tables_exist()
    con = db_conn()
    try:
        con.execute(
            """
            INSERT OR REPLACE INTO JumpboxPreference(ProfileName, Region, Env, TargetType, JumpboxId, UpdatedAtUtc)
            VALUES(?,?,?,?,?,?)
            """,
            (
                profile,
                region,
                (env or "OTHER").upper(),
                (target_type or "db").lower(),
                jumpbox_id,
                datetime.datetime.utcnow().isoformat() + "Z",
            ),
        )
        con.commit()
    finally:
        con.close()

# --------------------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------------------

def _append_job_file_log(job_id: str, text: str) -> None:
    try:
        with open(JOB_LOG_PATH, "a", encoding="utf-8", errors="ignore") as f:
            f.write(f"\n[{datetime.datetime.utcnow().isoformat()}Z] job={job_id}\n")
            f.write(text)
            if not text.endswith("\n"):
                f.write("\n")
    except Exception:
        pass


# --------------------------------------------------------------------------------------
# AWS CLI discovery
# --------------------------------------------------------------------------------------

def find_aws_exe() -> Optional[str]:
    import shutil

    override = (os.environ.get("AWS_CLI_PATH") or "").strip().strip('"')
    if override and os.path.isfile(override):
        return override

    p = shutil.which("aws")
    if p and os.path.isfile(p):
        return p

    if os.name == "nt":
        candidates = [
            r"C:\Program Files\Amazon\AWSCLIV2\aws.exe",
            r"C:\Program Files (x86)\Amazon\AWSCLIV2\aws.exe",
        ]
        la = os.environ.get("LOCALAPPDATA", "")
        if la:
            candidates.append(os.path.join(la, "Amazon", "AWSCLIV2", "aws.exe"))
        for c in candidates:
            if os.path.isfile(c):
                return c
        return None

    candidates = [
        "/opt/homebrew/bin/aws",
        "/usr/local/bin/aws",
        "/usr/bin/aws",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def aws_cmd_base() -> List[str]:
    aws = find_aws_exe()
    if not aws:
        raise RuntimeError(
            "AWS CLI not found.\n\n"
            "Please install AWS CLI v2.\n"
            "Or set AWS_CLI_PATH to full path of aws.\n"
        )
    return [aws]


# --------------------------------------------------------------------------------------
# AWS helpers
# --------------------------------------------------------------------------------------

def run_cmd(cmd: List[str], env: Optional[Dict[str, str]] = None, timeout: int = 1800) -> Tuple[int, str, str]:
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env or os.environ.copy(),
            shell=False,
        )
    except FileNotFoundError as e:
        return 127, "", (
            f"Command not found: {cmd[0]}\n{e}\n\n"
            "Fix: Install AWS CLI v2.\n"
            "Tip: If aws is installed but PATH is not updated, set AWS_CLI_PATH.\n"
        )
    except Exception as e:
        return 128, "", f"Failed to start command: {' '.join(cmd)}\n{e}"

    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        return 124, out, (err + "\nTIMEOUT")

    return p.returncode, out, err


def aws_cli_json(profile: str, region: str, service_args: List[str], log_cb) -> Any:
    cmd = aws_cmd_base() + service_args + ["--profile", profile, "--region", region, "--output", "json"]
    log_cb(f"$ {' '.join(shlex.quote(x) for x in cmd)}\n")
    code, out, err = run_cmd(cmd)
    if code != 0:
        raise RuntimeError(f"AWS CLI failed ({code})\n{(err or out).strip()}")
    try:
        return json.loads(out)
    except Exception as e:
        raise RuntimeError(f"Failed to parse AWS JSON: {e}\nRaw:\n{out[:2000]}")


def classify_ec2_platform(inst: Dict[str, Any]) -> str:
    plat = (inst.get("Platform") or "").lower()
    details = (inst.get("PlatformDetails") or "").lower()
    if "windows" in plat or "windows" in details:
        return "windows"
    return "linux"


def map_db_tech(engine: str) -> str:
    e = (engine or "").lower()
    if "sqlserver" in e:
        return "MSSQL"
    if "postgres" in e:
        return "PostgreSQL"
    if "mysql" in e or "mariadb" in e:
        return "MySQL"
    if "aurora" in e:
        return "Aurora"
    if "docdb" in e:
        return "DocDB"
    return "Other DB"


def map_cluster_group(engine: str) -> str:
    e = (engine or "").lower()
    if "docdb" in e:
        return "DocDB Cluster"
    if "postgres" in e:
        return "PostgreSQL Cluster"
    if "mysql" in e or "mariadb" in e:
        return "MySQL Cluster"
    if "aurora" in e:
        return "Aurora Cluster"
    return "Cluster"


def stable_local_port(seed: str, base: int = 30000, span: int = 20000) -> int:
    h = 0
    for ch in seed:
        h = (h * 131 + ord(ch)) & 0x7FFFFFFF
    return base + (h % span)


def infer_env(name: str) -> str:
    n = (name or "").lower().strip()
    if not n:
        return "OTHER"

    n = n.replace("-stg", "-stage").replace("_stg", "_stage")

    if "vnv" in n:
        return "VNV"
    if "perf" in n:
        return "PERF"
    if "preprod" in n:
        return "PREPROD"
    if "stage" in n or "stg" in n or "demo" in n:
        return "STAGE"
    if "qa" in n:
        return "QA"
    if "dev" in n:
        return "DEV"
    if "prod" in n or "prd" in n:
        return "PROD"
    return "OTHER"


# --------------------------------------------------------------------------------------
# Inventory (unchanged)
# --------------------------------------------------------------------------------------

def build_inventory(profile: str, region: str, log_cb) -> Dict[str, Any]:
    inv: Dict[str, Any] = {
        "profile": profile,
        "region": region,
        "generated_utc": datetime.datetime.utcnow().isoformat() + "Z",
        "ec2": [],
        "rds_instances": [],
        "rds_clusters": [],
        "docdb_clusters": [],
    }

    ec2 = aws_cli_json(profile, region, ["ec2", "describe-instances"], log_cb)
    seen_ec2 = set()
    for res in ec2.get("Reservations", []):
        for inst in res.get("Instances", []):
            iid = inst.get("InstanceId")
            if not iid or iid in seen_ec2:
                continue
            seen_ec2.add(iid)

            name = ""
            for t in inst.get("Tags", []) or []:
                if t.get("Key") == "Name":
                    name = t.get("Value") or ""
                    break

            state = (inst.get("State") or {}).get("Name", "unknown")
            platform = classify_ec2_platform(inst)

            remote_port = 3389 if platform == "windows" else 22
            local_port = stable_local_port(f"ec2|{profile}|{region}|{iid}|{remote_port}")

            inv["ec2"].append(
                {
                    "instance_id": iid,
                    "name": name or iid,
                    "state": state,
                    "platform": platform,
                    "remote_port": remote_port,
                    "local_port": local_port,
                    "target_id": iid,
                }
            )

    clu = aws_cli_json(profile, region, ["rds", "describe-db-clusters"], log_cb)
    seen_clu = set()
    for c in clu.get("DBClusters", []):
        cid = c.get("DBClusterIdentifier")
        if not cid or cid in seen_clu:
            continue
        seen_clu.add(cid)

        engine = c.get("Engine", "")
        endpoint = c.get("Endpoint") or ""
        port = c.get("Port") or 0
        status = c.get("Status", "") or "unknown"
        members = []
        for mem in c.get("DBClusterMembers", []) or []:
            mid = mem.get("DBInstanceIdentifier")
            if mid:
                members.append(mid)

        local_port = stable_local_port(f"rds_cluster|{profile}|{region}|{cid}|{port}")
        group = map_cluster_group(engine)

        inv["rds_clusters"].append(
            {
                "cluster_id": cid,
                "name": cid,
                "engine": engine,
                "tech": map_db_tech(engine),
                "cluster_group": group,
                "endpoint": endpoint,
                "port": int(port) if port else 0,
                "status": status,
                "local_port": local_port,
                "members": members,
                "target_id": cid,
            }
        )

    rds = aws_cli_json(profile, region, ["rds", "describe-db-instances"], log_cb)
    seen_rds = set()
    for db in rds.get("DBInstances", []):
        dbid = db.get("DBInstanceIdentifier")
        if not dbid or dbid in seen_rds:
            continue
        seen_rds.add(dbid)

        if db.get("DBClusterIdentifier"):
            continue

        engine = db.get("Engine", "")
        tech = map_db_tech(engine)
        endpoint = (db.get("Endpoint") or {}).get("Address", "")
        port = (db.get("Endpoint") or {}).get("Port", 0) or 0
        status = db.get("DBInstanceStatus", "") or "unknown"
        local_port = stable_local_port(f"rds|{profile}|{region}|{dbid}|{port}")

        inv["rds_instances"].append(
            {
                "db_id": dbid,
                "name": dbid,
                "engine": engine,
                "tech": tech,
                "endpoint": endpoint,
                "port": int(port) if port else 0,
                "status": status,
                "local_port": local_port,
                "target_id": dbid,
            }
        )

    # DocDB
    try:
        doc = aws_cli_json(profile, region, ["docdb", "describe-db-clusters"], log_cb)
        seen_doc = set()
        doc_map: Dict[str, Dict[str, Any]] = {}

        for c in doc.get("DBClusters", []):
            cid = c.get("DBClusterIdentifier")
            if not cid or cid in seen_doc:
                continue
            seen_doc.add(cid)

            endpoint = (c.get("Endpoint") or "").strip()
            port = int(c.get("Port") or 27017)
            status = c.get("Status", "") or "unknown"

            if port != 27017:
                continue
            if endpoint and ("docdb.amazonaws.com" not in endpoint):
                continue

            local_port = stable_local_port(f"docdb_cluster|{profile}|{region}|{cid}|{port}")

            rec = {
                "cluster_id": cid,
                "name": cid,
                "engine": "docdb",
                "tech": "DocDB",
                "cluster_group": "DocDB Cluster",
                "endpoint": endpoint,
                "port": 27017,
                "status": status,
                "local_port": local_port,
                "members": [],
                "target_id": cid,
            }
            inv["docdb_clusters"].append(rec)
            doc_map[cid] = rec

        try:
            inst = aws_cli_json(profile, region, ["docdb", "describe-db-instances"], log_cb)
            for d in inst.get("DBInstances", []):
                dbid = d.get("DBInstanceIdentifier")
                clid = d.get("DBClusterIdentifier")
                if not dbid or not clid:
                    continue
                if clid in doc_map:
                    doc_map[clid]["members"].append(dbid)
        except Exception:
            pass

    except Exception:
        pass

    return inv


def write_inventory_csv(inv: Dict[str, Any], csv_path: str):
    rows = []

    for it in inv["ec2"]:
        rows.append(
            {
                "type": "ec2",
                "profile": inv["profile"],
                "region": inv["region"],
                "id": it["instance_id"],
                "name": it["name"],
                "endpoint": "",
                "port": it["remote_port"],
                "local_port": it["local_port"],
                "status": it["state"],
                "engine": it["platform"],
            }
        )

    for it in inv["rds_instances"]:
        rows.append(
            {
                "type": "rds_instance",
                "profile": inv["profile"],
                "region": inv["region"],
                "id": it["db_id"],
                "name": it["name"],
                "endpoint": it["endpoint"],
                "port": it["port"],
                "local_port": it["local_port"],
                "status": it["status"],
                "engine": it["engine"],
            }
        )

    for it in inv["rds_clusters"]:
        rows.append(
            {
                "type": "rds_cluster",
                "profile": inv["profile"],
                "region": inv["region"],
                "id": it["cluster_id"],
                "name": it["name"],
                "endpoint": it["endpoint"],
                "port": it["port"],
                "local_port": it["local_port"],
                "status": it["status"],
                "engine": it["engine"],
            }
        )

    for it in inv.get("docdb_clusters", []):
        rows.append(
            {
                "type": "docdb_cluster",
                "profile": inv["profile"],
                "region": inv["region"],
                "id": it["cluster_id"],
                "name": it["name"],
                "endpoint": it["endpoint"],
                "port": it["port"],
                "local_port": it["local_port"],
                "status": it["status"],
                "engine": it["engine"],
            }
        )

    fieldnames = ["type", "profile", "region", "id", "name", "endpoint", "port", "local_port", "status", "engine"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

# --------------------------------------------------------------------------------------
# DB Upserts (unchanged)
# --------------------------------------------------------------------------------------

def upsert_profile(profile):
    con = db_conn()
    try:
        con.execute(
            """
            INSERT OR REPLACE INTO Profile(
              ProfileName, AuthType, SsoStartUrl, SsoRegion, AccountId, RoleName,
              DefaultRegion, OutputFormat, HasCredentials, IsEnabled
            )
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                profile.name,
                profile.auth_type,
                profile.sso_start_url or "",
                profile.sso_region or "",
                profile.account_id or "",
                profile.role_name or "",
                profile.region or "us-east-1",
                "json",
                1 if profile.has_credentials else 0,
                1,
            ),
        )
        con.commit()
    finally:
        con.close()


def _is_jumpbox_name(name: str) -> bool:
    nm = (name or "").lower()
    jump_keywords = [
        "jump", "jumpbox", "bastion", "bast",
        "ssm", "ssmhost", "ssm-host",
        "gateway", "gw", "proxy", "socks", "tunnel", "vpn", "connector",
    ]
    return any(k in nm for k in jump_keywords)


def _is_webui_name(name: str) -> bool:
    nm = (name or "").lower()
    return ("neo4j" in nm) or ("rabbit" in nm) or ("rmq" in nm)


def upsert_inventory_to_targets(inv: Dict[str, Any], profiles: List[AwsProfile]):
    now = datetime.datetime.utcnow().isoformat() + "Z"
    prof = next((p for p in profiles if p.name == inv["profile"]), None)
    env_from_profile = (prof.environment.upper() if prof else "OTHER")

    con = db_conn()
    try:
        for it in inv["ec2"]:
            name = it["name"]
            env = infer_env(name) if name else env_from_profile

            group = "EC2"
            if _is_webui_name(name):
                group = "Web UI"
            elif _is_jumpbox_name(name):
                group = "Jumpbox"

            target_id = f"ec2|{inv['profile']}|{inv['region']}|{it['instance_id']}"

            con.execute(
                """
                INSERT OR REPLACE INTO Target(
                  TargetId, ProfileName, DisplayName, TargetType, AwsTarget,
                  RemoteHost, RemotePort, LocalPort, Env, Region, GroupTitle,
                  Description, IsEnabled, SortOrder, CreatedAtUtc
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    target_id,
                    inv["profile"],
                    name or it["instance_id"],
                    "ec2",
                    it["instance_id"],
                    None,
                    int(it["remote_port"]),
                    int(it["local_port"]),
                    env,
                    inv["region"],
                    group,
                    f"state={it['state']} platform={it['platform']}",
                    1,
                    0,
                    now,
                ),
            )

        for it in inv["rds_instances"]:
            env = infer_env(it["name"]) if it["name"] else env_from_profile
            group = it["tech"] or "Other DB"
            target_id = f"rds_instance|{inv['profile']}|{inv['region']}|{it['db_id']}"

            con.execute(
                """
                INSERT OR REPLACE INTO Target(
                  TargetId, ProfileName, DisplayName, TargetType, AwsTarget,
                  RemoteHost, RemotePort, LocalPort, Env, Region, GroupTitle,
                  Description, IsEnabled, SortOrder, CreatedAtUtc
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    target_id,
                    inv["profile"],
                    it["name"] or it["db_id"],
                    "rds_instance",
                    it["db_id"],
                    it["endpoint"] or None,
                    int(it["port"]),
                    int(it["local_port"]),
                    env,
                    inv["region"],
                    group,
                    f"engine={it['engine']} status={it['status']}",
                    1,
                    0,
                    now,
                ),
            )

        for it in inv["rds_clusters"]:
            env = infer_env(it["name"]) if it["name"] else env_from_profile
            group = it.get("cluster_group") or map_cluster_group(it.get("engine") or "")
            members = it.get("members") or []
            target_id = f"rds_cluster|{inv['profile']}|{inv['region']}|{it['cluster_id']}"

            con.execute(
                """
                INSERT OR REPLACE INTO Target(
                  TargetId, ProfileName, DisplayName, TargetType, AwsTarget,
                  RemoteHost, RemotePort, LocalPort, Env, Region, GroupTitle,
                  Description, IsEnabled, SortOrder, CreatedAtUtc
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    target_id,
                    inv["profile"],
                    it["name"] or it["cluster_id"],
                    "rds_cluster",
                    it["cluster_id"],
                    it["endpoint"] or None,
                    int(it["port"]),
                    int(it["local_port"]),
                    env,
                    inv["region"],
                    group,
                    f"engine={it['engine']} status={it['status']} members={','.join(members)}",
                    1,
                    0,
                    now,
                ),
            )

        for it in inv.get("docdb_clusters", []):
            env = infer_env(it["name"]) if it["name"] else env_from_profile
            group = "DocDB Cluster"
            members = it.get("members") or []
            target_id = f"docdb_cluster|{inv['profile']}|{inv['region']}|{it['cluster_id']}"

            con.execute(
                """
                INSERT OR REPLACE INTO Target(
                  TargetId, ProfileName, DisplayName, TargetType, AwsTarget,
                  RemoteHost, RemotePort, LocalPort, Env, Region, GroupTitle,
                  Description, IsEnabled, SortOrder, CreatedAtUtc
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    target_id,
                    inv["profile"],
                    it["name"] or it["cluster_id"],
                    "docdb_cluster",
                    it["cluster_id"],
                    it["endpoint"] or None,
                    27017,
                    int(it["local_port"]),
                    env,
                    inv["region"],
                    group,
                    f"engine=docdb status={it['status']} members={','.join(members)}",
                    1,
                    0,
                    now,
                ),
            )

        con.commit()
    finally:
        con.close()

# --------------------------------------------------------------------------------------
# Catalog helpers (unchanged)
# --------------------------------------------------------------------------------------

def _parse_kv(desc: str, key: str) -> str:
    if not desc:
        return ""
    m = re.search(rf"\b{re.escape(key)}=([A-Za-z0-9._:-]+)", desc)
    return m.group(1) if m else ""


def _env_match_tokens(env: str) -> List[str]:
    e = (env or "").lower().strip()
    if not e:
        return []
    if e in ("stage", "stg"):
        return ["stage", "stg", "demo"]
    if e == "demo":
        return ["demo", "stage", "stg"]
    if e == "perf":
        return ["perf", "stage", "stg"]
    if e == "prod":
        return ["prod", "prd"]
    if e == "vnv":
        return ["vnv"]
    if e == "preprod":
        return ["preprod"]
    if e == "qa":
        return ["qa"]
    if e == "dev":
        return ["dev"]
    return [e]


def _load_catalog_for(profile: str, region: str) -> Dict[str, Any]:
    if not os.path.exists(CATALOG_JSON_PATH):
        return {}
    try:
        with open(CATALOG_JSON_PATH, "r", encoding="utf-8") as f:
            cat = json.load(f)
        if cat.get("profile") != profile or cat.get("region") != region:
            return {}
        return cat
    except Exception:
        return {}


def _get_jumpboxes_from_catalog(profile: str, region: str) -> List[Dict[str, Any]]:
    cat = _load_catalog_for(profile, region)
    jump_list = (cat.get("ec2_grouped", {}) or {}).get("Jumpbox", []) or []
    out = []
    for j in jump_list:
        out.append(
            {
                "name": j.get("name") or "",
                "instance_id": (j.get("instance_id") or j.get("aws_target") or "").strip(),
                "env": (j.get("env") or "OTHER").upper(),
                "state": (j.get("state") or "unknown").lower(),
            }
        )
    seen = set()
    uniq = []
    for x in out:
        if not x["instance_id"]:
            continue
        k = x["instance_id"]
        if k in seen:
            continue
        seen.add(k)
        uniq.append(x)
    return uniq


def _jumpbox_exists_in_catalog(profile: str, region: str, jumpbox_id: str) -> bool:
    if not jumpbox_id:
        return False
    for j in _get_jumpboxes_from_catalog(profile, region):
        if (j.get("instance_id") or "").strip() == jumpbox_id.strip():
            return True
    return False


def pick_jumpbox_instance_id(profile: str, region: str, env: str) -> Optional[str]:
    cat = _load_catalog_for(profile, region)
    jump_list = (cat.get("ec2_grouped", {}) or {}).get("Jumpbox", []) or []
    if not jump_list:
        return None

    tokens = _env_match_tokens(env)

    def score(j) -> int:
        nm = (j.get("name") or "").lower()
        s = 0
        for t in tokens:
            if re.search(rf"(^|[^a-z0-9]){re.escape(t)}([^a-z0-9]|$)", nm):
                s += 100 if t == tokens[0] else 50
        if "ssm" in nm:
            s += 10
        if "jumpbox" in nm or "bastion" in nm or "jump" in nm:
            s += 5
        return s

    best = max(jump_list, key=score)
    if score(best) > 0:
        return (best.get("instance_id") or best.get("aws_target") or "").strip() or None

    j0 = jump_list[0]
    return (j0.get("instance_id") or j0.get("aws_target") or "").strip() or None


def pick_docdb_jumpbox_instance_id(profile: str, region: str, env: str) -> Optional[str]:
    cat = _load_catalog_for(profile, region)
    jump_list = (cat.get("ec2_grouped", {}) or {}).get("Jumpbox", []) or []
    if not jump_list:
        return None

    tokens = _env_match_tokens(env)

    def score(j) -> int:
        nm = (j.get("name") or "").lower()
        if "docdb" not in nm:
            return 0
        s = 500
        if "jumpbox" in nm or "bastion" in nm or re.search(r"\bjump\b", nm):
            s += 200
        for t in tokens:
            if re.search(rf"(^|[^a-z0-9]){re.escape(t)}([^a-z0-9]|$)", nm):
                s += 50
        return s

    best = max(jump_list, key=score)
    if score(best) > 0:
        return (best.get("instance_id") or best.get("aws_target") or "").strip() or None
    return None


def pick_jumpbox_for_target(profile: str, region: str, env: str, target_type: str) -> Optional[str]:
    tt = (target_type or "db").lower().strip()
    env_up = (env or "OTHER").upper()

    preferred = get_jumpbox_preference(profile, region, env_up, tt)
    if preferred and _jumpbox_exists_in_catalog(profile, region, preferred):
        return preferred

    if tt == "docdb_cluster":
        jb = pick_docdb_jumpbox_instance_id(profile, region, env_up)
        if jb:
            return jb
    return pick_jumpbox_instance_id(profile, region, env_up)


def targets_to_catalog_json(profile: str, region: str) -> Dict[str, Any]:
    con = db_conn()
    try:
        rows = con.execute(
            """
            SELECT * FROM Target
            WHERE ProfileName=? AND IFNULL(Region,'')=?
              AND IsEnabled=1
            """,
            (profile, region),
        ).fetchall()
    finally:
        con.close()

    db_grouped: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    ec2_grouped: Dict[str, List[Dict[str, Any]]] = {"Web UI": [], "Jumpbox": [], "EC2": []}

    for r in rows:
        ttype = (r["TargetType"] or "").lower()
        env = (r["Env"] or "OTHER").upper()
        group = r["GroupTitle"] or "Other"
        desc = r["Description"] or ""

        if ttype in ("rds_instance", "rds_cluster", "docdb_cluster"):
            status = _parse_kv(desc, "status") or "unknown"
            engine = _parse_kv(desc, "engine") or ""
            endpoint = (r["RemoteHost"] or "").strip()
            remote_port = int(r["RemotePort"] or 0)

            can_forward = (status.lower() in ("available", "running"))

            db_grouped.setdefault(group, {}).setdefault(env, []).append(
                {
                    "name": r["DisplayName"],
                    "endpoint": endpoint,
                    "remote_port": remote_port,
                    "local_port": int(r["LocalPort"] or 0),
                    "aws_target": r["AwsTarget"],
                    "target_type": r["TargetType"],
                    "env": env,
                    "status": status,
                    "engine": engine,
                    "members": [],
                    "can_forward": can_forward,
                }
            )

        elif ttype == "ec2":
            group_title = r["GroupTitle"] or "EC2"
            bucket = group_title if group_title in ec2_grouped else "EC2"

            state = _parse_kv(desc, "state") or "unknown"
            can_forward = (state.lower() == "running")

            ec2_grouped[bucket].append(
                {
                    "name": r["DisplayName"],
                    "instance_id": r["AwsTarget"],
                    "remote_port": int(r["RemotePort"] or 0),
                    "local_port": int(r["LocalPort"] or 0),
                    "aws_target": r["AwsTarget"],
                    "target_type": r["TargetType"],
                    "env": env,
                    "state": state,
                    "can_forward": can_forward,
                }
            )

    return {
        "profile": profile,
        "region": region,
        "generated_utc": datetime.datetime.utcnow().isoformat() + "Z",
        "db_grouped": db_grouped,
        "ec2_grouped": ec2_grouped,
    }

# --------------------------------------------------------------------------------------
# Update jobs (unchanged)
# --------------------------------------------------------------------------------------

def job_log_append(job_id: str, text: str):
    ensure_tables_exist()
    con = db_conn()
    try:
        row = con.execute("SELECT LogText FROM UpdateJob WHERE JobId=?", (job_id,)).fetchone()
        old = row["LogText"] if row else ""
        new = (old or "") + text
        now = datetime.datetime.utcnow().isoformat() + "Z"
        con.execute(
            "UPDATE UpdateJob SET LogText=?, LastUpdateUtc=? WHERE JobId=?",
            (new, now, job_id),
        )
        con.commit()
    finally:
        con.close()

    _append_job_file_log(job_id, text)


def job_set_status(job_id: str, status: str, pid: Optional[int] = None):
    ensure_tables_exist()
    con = db_conn()
    try:
        now = datetime.datetime.utcnow().isoformat() + "Z"
        if pid is None:
            con.execute(
                "UPDATE UpdateJob SET Status=?, LastUpdateUtc=? WHERE JobId=?",
                (status, now, job_id),
            )
        else:
            con.execute(
                "UPDATE UpdateJob SET Status=?, Pid=?, LastUpdateUtc=? WHERE JobId=?",
                (status, int(pid), now, job_id),
            )
        con.commit()
    finally:
        con.close()


def start_update_job(profile: str, region: str) -> str:
    ensure_tables_exist()
    job_id = str(uuid.uuid4())
    con = db_conn()
    try:
        con.execute(
            """
            INSERT INTO UpdateJob(JobId, ProfileName, Region, Status, Pid, CreatedAtUtc, LastUpdateUtc, LogText)
            VALUES(?,?,?,?,?,datetime('now'),datetime('now'),'')
            """,
            (job_id, profile, region, "starting", 0),
        )
        con.commit()
    finally:
        con.close()

    def worker():
        try:
            job_set_status(job_id, "running", os.getpid())

            def log_cb(s: str):
                job_log_append(job_id, s)

            inv = build_inventory(profile, region, log_cb)

            ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            safe_profile = re.sub(r"[^A-Za-z0-9._-]+", "_", profile)
            safe_region = re.sub(r"[^A-Za-z0-9._-]+", "_", region)
            csv_path = os.path.join(EXPORT_DIR, f"aws_inventory_{safe_profile}_{safe_region}_{ts}.csv")
            write_inventory_csv(inv, csv_path)

            profiles = load_profiles()
            for p in profiles:
                upsert_profile(p)

            upsert_inventory_to_targets(inv, profiles)

            catalog = targets_to_catalog_json(profile, region)
            with open(CATALOG_JSON_PATH, "w", encoding="utf-8") as f:
                json.dump(catalog, f, indent=2)

            job_set_status(job_id, "completed")
        except Exception as e:
            job_set_status(job_id, "failed")
            job_log_append(job_id, "\nFAILED:\n" + str(e) + "\n")

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return job_id


def get_latest_job(profile: str, region: str) -> Optional[Dict[str, Any]]:
    ensure_tables_exist()
    con = db_conn()
    try:
        row = con.execute(
            """
            SELECT * FROM UpdateJob
            WHERE ProfileName=? AND Region=?
            ORDER BY datetime(LastUpdateUtc) DESC, datetime(CreatedAtUtc) DESC
            LIMIT 1
            """,
            (profile, region),
        ).fetchone()
        if not row:
            return None
        return {
            "job_id": row["JobId"],
            "status": row["Status"],
            "pid": row["Pid"],
            "last_update": row["LastUpdateUtc"],
        }
    finally:
        con.close()

# --------------------------------------------------------------------------------------
# Jumpbox API (unchanged)
# --------------------------------------------------------------------------------------

@app.route("/api/jumpboxes", methods=["GET"])
def api_jumpboxes():
    profile = (request.args.get("profile") or "").strip()
    region = (request.args.get("region") or "").strip()
    env = (request.args.get("env") or "OTHER").strip().upper()

    if not profile or not region:
        return jsonify({"ok": False, "error": "Missing profile/region"}), 400

    jumpboxes = _get_jumpboxes_from_catalog(profile, region)
    tokens = _env_match_tokens(env)

    def env_score(j):
        nm = (j.get("name") or "").lower()
        s = 0
        for t in tokens:
            if re.search(rf"(^|[^a-z0-9]){re.escape(t)}([^a-z0-9]|$)", nm):
                s += 100 if t == tokens[0] else 50
        if (j.get("state") or "") == "running":
            s += 10
        if "jumpbox" in nm or "bastion" in nm or "jump" in nm or "ssm" in nm:
            s += 5
        return s

    jumpboxes_sorted = sorted(jumpboxes, key=env_score, reverse=True)
    return jsonify({"ok": True, "jumpboxes": jumpboxes_sorted})


@app.route("/api/jumpbox/get", methods=["GET"])
def api_jumpbox_get():
    profile = (request.args.get("profile") or "").strip()
    region = (request.args.get("region") or "").strip()
    env = (request.args.get("env") or "OTHER").strip().upper()
    target_type = (request.args.get("target_type") or "db").strip().lower()

    if not profile or not region:
        return jsonify({"ok": False, "error": "Missing profile/region"}), 400

    saved = get_jumpbox_preference(profile, region, env, target_type) or ""
    if saved and _jumpbox_exists_in_catalog(profile, region, saved):
        return jsonify({"ok": True, "effective_jumpbox_id": saved, "source": "saved"})

    auto = pick_jumpbox_for_target(profile, region, env, target_type) or ""
    return jsonify({"ok": True, "effective_jumpbox_id": auto, "source": "auto"})


@app.route("/api/jumpbox/set", methods=["POST"])
def api_jumpbox_set():
    data = request.get_json(force=True, silent=True) or {}
    profile = (data.get("profile") or "").strip()
    region = (data.get("region") or "").strip()
    env = (data.get("env") or "OTHER").strip().upper()
    target_type = (data.get("target_type") or "db").strip().lower()
    jumpbox_id = (data.get("jumpbox_id") or "").strip()

    if not profile or not region or not jumpbox_id:
        return jsonify({"ok": False, "error": "Missing profile/region/jumpbox_id"}), 400

    if not _jumpbox_exists_in_catalog(profile, region, jumpbox_id):
        return jsonify({"ok": False, "error": "Selected jumpbox not found in current catalog. Please refresh catalog and try again."}), 400

    set_jumpbox_preference(profile, region, env, target_type, jumpbox_id)
    return jsonify({"ok": True})

# --------------------------------------------------------------------------------------
# SSM (macOS Terminal-based)
# --------------------------------------------------------------------------------------

def _open_cmd_window(cmd: List[str], title: str = "SSM"):
    """
    Windows: opens new cmd window
    macOS: opens Terminal.app and runs the command (interactive)
    Linux: tries x-terminal-emulator / gnome-terminal / xterm if available
    """
    if os.name == "nt":
        full = ["cmd", "/c", "start", title] + cmd
        subprocess.Popen(full, shell=False)
        return

    if sys.platform == "darwin":
        cmd_str = " ".join(shlex.quote(x) for x in cmd)
        # Escape for AppleScript string literal
        cmd_str_escaped = cmd_str.replace("\\", "\\\\").replace('"', '\\"')
        apple_script = f'''
        tell application "Terminal"
            activate
            do script "{cmd_str_escaped}"
        end tell
        '''
        subprocess.Popen(["osascript", "-e", apple_script], shell=False)
        return

    cmd_str = " ".join(shlex.quote(x) for x in cmd)
    terminal_candidates = [
        ["x-terminal-emulator", "-e", "bash", "-lc", cmd_str],
        ["gnome-terminal", "--", "bash", "-lc", cmd_str],
        ["konsole", "-e", "bash", "-lc", cmd_str],
        ["xterm", "-e", cmd_str],
    ]
    for tcmd in terminal_candidates:
        try:
            subprocess.Popen(tcmd, shell=False)
            return
        except Exception:
            continue

    subprocess.Popen(cmd, shell=False)


def start_ssm_shell(profile: str, region: str, instance_id: str) -> None:
    aws = aws_cmd_base()[0]
    cmd = [
        aws, "ssm", "start-session",
        "--profile", profile,
        "--region", region,
        "--target", instance_id,
    ]
    _open_cmd_window(cmd, title=f"SSM Shell {instance_id}")


def start_ssm_port_forward_ec2(
    profile: str,
    region: str,
    instance_id: str,
    remote_port: int,
    local_port: int,
):
    aws = aws_cmd_base()[0]
    cmd = [
        aws, "ssm", "start-session",
        "--profile", profile,
        "--region", region,
        "--target", instance_id,
        "--document-name", "AWS-StartPortForwardingSession",
        "--parameters", f'portNumber=["{int(remote_port)}"],localPortNumber=["{int(local_port)}"]',
    ]
    _open_cmd_window(cmd, title=f"SSM PF {instance_id}:{remote_port}->{local_port}")


def start_ssm_port_forward_remote_host(
    profile: str,
    region: str,
    jumpbox_instance_id: str,
    remote_host: str,
    remote_port: int,
    local_port: int,
):
    aws = aws_cmd_base()[0]
    cmd = [
        aws, "ssm", "start-session",
        "--profile", profile,
        "--region", region,
        "--target", jumpbox_instance_id,
        "--document-name", "AWS-StartPortForwardingSessionToRemoteHost",
        "--parameters",
        (
            f'host=["{remote_host}"],'
            f'portNumber=["{int(remote_port)}"],'
            f'localPortNumber=["{int(local_port)}"]'
        ),
    ]
    _open_cmd_window(cmd, title=f"SSM DB PF {remote_host}:{remote_port}->{local_port}")

# --------------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    profiles = load_profiles()

    profile_name = request.args.get("profile", "").strip()
    region = request.args.get("region", "").strip()

    if not profile_name:
        return render_template(
            "index.html",
            mode="profiles",
            profiles=profiles,
            selected_profile=None,
            available_regions=DEFAULT_REGIONS,
            selected_region="",
            update_job=None,
        )

    selected_profile = next((p for p in profiles if p.name == profile_name), None)
    if not selected_profile:
        flash(f"Profile not found: {profile_name}", "danger")
        return redirect(url_for("index"))

    selected_region = region or selected_profile.region or "us-east-1"

    db_grouped = {}
    ec2_grouped = {}
    catalog_matches = False

    if os.path.exists(CATALOG_JSON_PATH):
        try:
            with open(CATALOG_JSON_PATH, "r", encoding="utf-8") as f:
                cat = json.load(f)
            if cat.get("profile") == profile_name and cat.get("region") == selected_region:
                catalog_matches = True
                db_grouped = cat.get("db_grouped", {}) or {}
                ec2_grouped = cat.get("ec2_grouped", {}) or {}
        except Exception:
            pass

    update_job = get_latest_job(profile_name, selected_region)
    if update_job and update_job.get("status") not in ("starting", "running"):
        update_job = None

    if not catalog_matches and update_job is None:
        try:
            _ = start_update_job(profile_name, selected_region)
            update_job = get_latest_job(profile_name, selected_region)
            flash(f"Building catalog for region {selected_region}…", "info")
        except Exception as e:
            flash(f"Could not start catalog build for {selected_region}:\n{e}", "danger")

    return render_template(
        "index.html",
        mode="dashboard",
        profiles=profiles,
        selected_profile=selected_profile,
        available_regions=DEFAULT_REGIONS,
        selected_region=selected_region,
        db_grouped=db_grouped,
        ec2_grouped=ec2_grouped,
        update_job=update_job,
    )


@app.route("/sync-profiles", methods=["POST"])
def sync_profiles():
    flash("Profiles refreshed from ~/.aws config/credentials.", "success")
    return redirect(url_for("index"))


@app.route("/sso-login", methods=["POST"])
def sso_login():
    try:
        profile = request.form.get("profile", "").strip()
        if not profile:
            flash("Missing profile.", "danger")
            return redirect(url_for("index"))

        profiles = load_profiles()
        p = next((x for x in profiles if x.name == profile), None)
        if not p:
            flash(f"Profile not found: {profile}", "danger")
            return redirect(url_for("index"))

        cmd = aws_cmd_base() + ["sso", "login", "--profile", profile]
        code, out, err = run_cmd(cmd, timeout=900)
        if code != 0:
            msg = (err or out or "").strip() or f"AWS CLI returned exit code {code}"
            flash(f"SSO login failed for profile '{profile}'.\n\n{msg}", "danger")
            return redirect(url_for("index"))

        flash("SSO login completed successfully.", "success")

        default_region = p.region or "us-east-1"
        _ = start_update_job(profile, default_region)
        return redirect(url_for("index", profile=profile, region=default_region))
    except Exception as e:
        flash(f"SSO login error:\n{e}", "danger")
        return redirect(url_for("index"))


@app.route("/update-catalog/status/<job_id>", methods=["GET"])
def update_catalog_status(job_id: str):
    ensure_tables_exist()
    con = db_conn()
    try:
        row = con.execute("SELECT * FROM UpdateJob WHERE JobId=?", (job_id,)).fetchone()
        if not row:
            return jsonify({"status": "failed"}), 404
        return jsonify(
            {
                "job_id": row["JobId"],
                "status": row["Status"],
                "last_update": row["LastUpdateUtc"],
            }
        )
    finally:
        con.close()


@app.route("/ssm-shell", methods=["POST"])
def ssm_shell():
    profile = request.form.get("profile", "").strip()
    region = request.form.get("region", "").strip() or "us-east-1"
    instance_id = request.form.get("instance_id", "").strip()

    if not profile or not instance_id:
        flash("Missing profile or instance_id for SSM Shell.", "danger")
        return redirect(request.referrer or url_for("index"))

    try:
        start_ssm_shell(profile, region, instance_id)
        flash(f"Started SSM Shell for {instance_id}", "success")
    except Exception as e:
        flash(f"SSM Shell failed:\n{e}", "danger")

    return redirect(request.referrer or url_for("index"))


@app.route("/ssm-forward", methods=["POST"])
def ssm_forward():
    profile = request.form.get("profile", "").strip()
    region = request.form.get("region", "").strip() or "us-east-1"

    target_type = request.form.get("target_type", "").strip()

    remote_host = (request.form.get("remote_host", "") or "").strip()
    remote_port = int(request.form.get("remote_port", "0") or "0")
    local_port = int(request.form.get("local_port", "0") or "0")
    env = (request.form.get("env", "") or "OTHER").strip()

    can_forward = (request.form.get("can_forward", "1") or "1").strip()
    if can_forward == "0":
        flash("DB is not available/running.", "warning")
        return redirect(request.referrer or url_for("index"))

    if not profile or not remote_host or remote_port <= 0 or local_port <= 0:
        flash(
            "Missing required inputs for DB Port Forward.\n"
            f"profile={profile} remote_host={remote_host} remote_port={remote_port} local_port={local_port}",
            "danger",
        )
        return redirect(request.referrer or url_for("index"))

    jumpbox_id = pick_jumpbox_for_target(profile, region, env, target_type)
    if not jumpbox_id:
        if (target_type or "").lower() == "docdb_cluster":
            flash(
                "No DocDB Jumpbox found for this profile/region.\n"
                "Fix: Ensure a Jumpbox exists with name containing 'docdb' and 'jumpbox' (or bastion/jump).",
                "danger",
            )
        else:
            flash(
                "No Jumpbox found for this profile/region.\n"
                "Fix: Ensure at least one EC2 instance is categorized as Jumpbox (name contains jump/bastion/ssm/etc) "
                "and that it is running + SSM managed.",
                "danger",
            )
        return redirect(request.referrer or url_for("index"))

    try:
        start_ssm_port_forward_remote_host(
            profile=profile,
            region=region,
            jumpbox_instance_id=jumpbox_id,
            remote_host=remote_host,
            remote_port=remote_port,
            local_port=local_port,
        )
        flash(
            f"Starting DB tunnel via Jumpbox {jumpbox_id} -> {remote_host}:{remote_port} on localhost:{local_port}",
            "success",
        )
    except Exception as e:
        flash(f"DB port forward failed:\n{e}", "danger")

    return redirect(request.referrer or url_for("index"))


@app.route("/webui-forward", methods=["POST"])
def webui_forward():
    """
    Desktop-window only requirement:
    - We still start the tunnel exactly the same.
    - We do NOT auto-open a browser tab/window.
    - User can access the forwarded URL inside the embedded UI (same app window),
      since the webview is already pointed at the Flask UI.
    """
    profile = request.form.get("profile", "").strip()
    region = request.form.get("region", "").strip() or "us-east-1"
    instance_id = request.form.get("instance_id", "").strip()
    local_port = int(request.form.get("local_port", "0") or "0")
    can_forward = (request.form.get("can_forward", "1") or "1").strip()

    if can_forward == "0":
        flash("Instance is not running.", "warning")
        return redirect(request.referrer or url_for("index"))

    if not profile or not instance_id or local_port <= 0:
        flash("Missing required inputs for Web UI Port Forward.", "danger")
        return redirect(request.referrer or url_for("index"))

    try:
        start_ssm_port_forward_ec2(
            profile=profile,
            region=region,
            instance_id=instance_id,
            remote_port=8080,
            local_port=local_port,
        )
        flash(
            f"Starting Web UI tunnel. You can open: http://127.0.0.1:{local_port}/",
            "success",
        )
    except Exception as e:
        flash(f"Web UI port forward failed:\n{e}", "danger")

    return redirect(request.referrer or url_for("index"))

# --------------------------------------------------------------------------------------
# Desktop runner (pywebview) - desktop window only
# --------------------------------------------------------------------------------------

def _serve_flask(host: str, port: int):
    """
    Run the local Flask server for the embedded UI.
    Prefer Waitress for production-like stability; fallback to Flask dev server.
    """
    try:
        from waitress import serve  # type: ignore
        serve(app, host=host, port=port, threads=8)
    except Exception:
        # Fallback (dev server). Still OK for local desktop usage.
        app.run(host=host, port=port, debug=False, threaded=True)


def run_desktop():
    """
    Starts Flask in a background thread, then opens a native desktop window
    that renders the Flask UI (no external browser).
    """
    host = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
    port = int(os.environ.get("DASHBOARD_PORT", "5050"))

    # Start local server in background
    t = threading.Thread(target=_serve_flask, args=(host, port), daemon=True)
    t.start()

    # Launch desktop window
    try:
        import webview  # pywebview
    except Exception as e:
        raise RuntimeError(
            "pywebview is not installed, but desktop UI mode is enabled.\n"
            "Install pywebview or add it to requirements.txt.\n\n"
            f"Error: {e}"
        )

    url = f"http://{host}:{port}/"
    webview.create_window(
        APP_TITLE,
        url,
        width=1200,
        height=780,
        resizable=True,
        confirm_close=True,
    )
    # debug=False to avoid extra noise
    webview.start(debug=False)


if __name__ == "__main__":
    run_desktop()