import os
import io
import re
import time
import json
import shlex
import posixpath
import stat
import getpass
import queue
from typing import Optional, List, Tuple, Dict, Any
from random import randint
from concurrent.futures import ThreadPoolExecutor

import paramiko
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

app = FastAPI(title="Remote Script Control")

BASE_DIR = os.path.dirname(__file__)

# CORS (adjust in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =================== Local config for scripts area ===================

CONFIG_PATH = os.getenv("APP_CONFIG", os.path.join(BASE_DIR, "config.json"))

DEFAULT_CONFIG: Dict[str, Any] = {
    "defaults": {
        "hint_candidates": ["readme", "readme.txt", "README", "README.txt"],
        "result_candidates": ["results.txt", "results", "RESULTS.txt", "RESULTS"],
        "timeout": 900,
        "env": {},
        "args_template": None,
        "pre_write_input": False,
        "input_template": None,
        "input_values_file": None
    },
    "projects": {}
}

def load_local_config() -> Dict[str, Any]:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if "defaults" not in cfg or not isinstance(cfg["defaults"], dict):
            cfg["defaults"] = DEFAULT_CONFIG["defaults"]
        if "projects" not in cfg or not isinstance(cfg["projects"], dict):
            cfg["projects"] = {}
        return cfg
    except FileNotFoundError:
        return DEFAULT_CONFIG.copy()
    except Exception:
        return DEFAULT_CONFIG.copy()

def dict_merge(base: Dict[str, Any], extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out = dict(base or {})
    if extra:
        for k, v in extra.items():
            if k == "env" and isinstance(v, dict):
                env = dict(out.get("env", {}))
                env.update(v)
                out["env"] = env
            else:
                out[k] = v
    return out

def get_project_settings(cfg: Dict[str, Any], project: str) -> Dict[str, Any]:
    projects = cfg.get("projects", {})
    return projects.get(project, {}) if isinstance(projects.get(project), dict) else {}

def get_script_overrides(cfg: Dict[str, Any], project: str, script: str) -> Dict[str, Any]:
    projects = cfg.get("projects", {})
    wild = (projects.get("*", {}) or {}).get("scripts", {})
    proj = (projects.get(project, {}) or {}).get("scripts", {})
    ov = {}
    if isinstance(wild, dict) and script in wild:
        ov = dict_merge(ov, wild[script])
    if isinstance(proj, dict) and script in proj:
        ov = dict_merge(ov, proj[script])
    return ov

def get_effective_rule(cfg: Dict[str, Any], project: str, script: str) -> Dict[str, Any]:
    defaults = cfg.get("defaults", DEFAULT_CONFIG["defaults"])
    rule = get_script_overrides(cfg, project, script)
    return dict_merge(defaults, rule)

# =================== Remote environment ===================

SSH_HOST = os.getenv("SSH_HOST", "10.11.116.40")
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
SSH_USERNAME = os.getenv("SSH_USERNAME", "bullkpsa_G2R0C0")
SSH_PASSWORD = os.getenv("SSH_PASSWORD", "bullkpsa_G2R0C001")

SSH_PRIVATE_KEY = os.getenv("SSH_PRIVATE_KEY")
SSH_PRIVATE_KEY_PASSPHRASE = os.getenv("SSH_PRIVATE_KEY_PASSPHRASE")

# Handshake timeouts
SSH_CONNECT_TIMEOUT = int(os.getenv("SSH_CONNECT_TIMEOUT", "60"))
SSH_BANNER_TIMEOUT = int(os.getenv("SSH_BANNER_TIMEOUT", "60"))
SSH_AUTH_TIMEOUT   = int(os.getenv("SSH_AUTH_TIMEOUT", "60"))

# Scripts area base + helper
ROOT_BASE_DIR = os.getenv("ROOT_BASE_DIR", "/home/bullkpsa_G2R0C0/users/naser")
LAST_RUN_STATE = ".last_run.json"
ACTIVITY_LOG_NAME = "activity.log"
LOCAL_USER = getpass.getuser()

LOCAL_ACTIVITY_LOG = os.getenv("LOCAL_ACTIVITY_LOG", os.path.join(BASE_DIR, "activity.log"))

def _root_base_for_server_meta(server_meta: Optional[Dict[str, Any]]) -> str:
    # Option B: always use configured ROOT_BASE_DIR for the scripts area
    return ROOT_BASE_DIR

# =================== ANSI/control-char stripping ===================

ANSI_ESCAPE_RE = re.compile(
    r"(?:\x1B[@-Z\\-_]|\x1B\[[0-?]*[ -/]*[@-~]|\x9B[0-?]*[ -/]*[@-~]|\x1B\][^\x1B\x07]*(?:\x1B\\|\x07)|\x1B[P^_][^\x1B]*(?:\x1B\\)|\x1B\\)"
)
CONTROL_RE = re.compile(r"[\x00-\x08\x0B-\x1F\x7F-\x9F]")

def strip_ansi(s: Optional[str]) -> str:
    if not s:
        return ""
    try:
        s = ANSI_ESCAPE_RE.sub("", s)
        s = CONTROL_RE.sub("", s)
        return s
    except Exception:
        return s

# =================== SSH helpers ===================

def load_private_key(pem: str, passphrase: Optional[str]) -> paramiko.PKey:
    for key_cls in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key):
        try:
            return key_cls.from_private_key(io.StringIO(pem), password=passphrase)
        except Exception:
            continue
    raise ValueError("Unsupported or invalid private key")

def _connect(client: paramiko.SSHClient, host: str, port: int, username: str):
    if SSH_PRIVATE_KEY:
        pkey = load_private_key(SSH_PRIVATE_KEY, SSH_PRIVATE_KEY_PASSPHRASE)
        client.connect(
            host, port=port, username=username, pkey=pkey,
            look_for_keys=False, allow_agent=False,
            timeout=SSH_CONNECT_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT, auth_timeout=SSH_AUTH_TIMEOUT,
        )
    else:
        if not SSH_PASSWORD:
            raise HTTPException(status_code=500, detail="SSH password not configured")
        client.connect(
            host, port=port, username=username, password=SSH_PASSWORD,
            look_for_keys=False, allow_agent=False,
            timeout=SSH_CONNECT_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT, auth_timeout=SSH_AUTH_TIMEOUT,
        )

def ssh_client() -> paramiko.SSHClient:
    if not SSH_USERNAME or (not SSH_PASSWORD and not SSH_PRIVATE_KEY):
        raise HTTPException(status_code=500, detail="SSH credentials are not configured")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        _connect(client, SSH_HOST, SSH_PORT, SSH_USERNAME)
        return client
    except Exception as e:
        client.close()
        raise HTTPException(status_code=502, detail=f"SSH connection failed: {e}")

def ssh_client_for_server(server: Dict[str, Any]) -> paramiko.SSHClient:
    host = server.get("host")
    port = int(server.get("port") or 22)
    username = server.get("username") or SSH_USERNAME
    if not host or not username:
        raise HTTPException(status_code=400, detail="Server entry missing host/username")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        _connect(client, host, port, username)
        return client
    except Exception as e:
        client.close()
        raise HTTPException(status_code=502, detail=f"SSH connection failed for {server.get('id')}: {e}")

def ensure_within_root(path: str) -> str:
    normalized = posixpath.normpath(path)
    root = ROOT_BASE_DIR.rstrip("/")
    if normalized == root or normalized.startswith(root + "/"):
        return normalized
    raise HTTPException(status_code=403, detail="Path outside allowed root directory")

def base_for_subdir(subdir: str, sftp: Optional[paramiko.SFTPClient] = None) -> str:
    if not subdir or "/" in subdir or "\\" in subdir or ".." in subdir:
        raise HTTPException(status_code=400, detail="Invalid subdir name")
    base = ensure_within_root(posixpath.join(ROOT_BASE_DIR, subdir))
    if sftp:
        try:
            st = sftp.stat(base)
            if not stat.S_ISDIR(st.st_mode):
                raise HTTPException(status_code=400, detail="subdir is not a directory")
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="subdir not found")
    return base

def ensure_within_base(base_dir: str, path: str) -> str:
    if not path.startswith("/"):
        path = posixpath.join(base_dir, path)
    normalized = posixpath.normpath(path)
    base_norm = base_dir.rstrip("/")
    if normalized == base_norm or normalized.startswith(base_norm + "/"):
        return normalized
    raise HTTPException(status_code=403, detail="Path outside selected subdir")

def ssh_exec(client: paramiko.SSHClient, command: str, timeout: int = 600, stdin_data: Optional[str] = None):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    if stdin_data is not None:
        try:
            data = stdin_data
            if data and not data.endswith("\n"):
                data += "\n"
            stdin.write(data)
            stdin.flush()
        except Exception:
            pass
    out = strip_ansi(stdout.read().decode("utf-8", errors="replace"))
    err = strip_ansi(stderr.read().decode("utf-8", errors="replace"))
    exit_status = stdout.channel.recv_exit_status()
    return out, err, exit_status

def ssh_exec_interactive_autopass(
    client: paramiko.SSHClient,
    command: str,
    timeout: int,
    password: str,
    prompt_patterns: List[str],
    max_injections: int = 20,
    pre_stdin: Optional[str] = None
) -> Tuple[str, str, int]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=True)
    channel = stdout.channel
    regs = [re.compile(p, re.IGNORECASE) for p in (prompt_patterns or [])]
    out_buf = ""
    err_buf = ""
    scan_buf = ""
    injections = 0

    if pre_stdin is not None:
        try:
            data = pre_stdin
            if data and not data.endswith("\n"):
                data += "\n"
            stdin.write(data)
            stdin.flush()
        except Exception:
            pass

    start = time.time()
    while True:
        if channel.exit_status_ready():
            while channel.recv_ready():
                chunk = channel.recv(4096).decode("utf-8", errors="replace")
                out_buf += chunk
                scan_buf = (scan_buf + chunk)[-2048:]
            while channel.recv_stderr_ready():
                chunk = channel.recv_stderr(4096).decode("utf-8", errors="replace")
                err_buf += chunk
                scan_buf = (scan_buf + chunk)[-2048:]
            break

        if channel.recv_ready():
            chunk = channel.recv(4096).decode("utf-8", errors="replace")
            out_buf += chunk
            scan_buf = (scan_buf + chunk)[-2048:]

        if channel.recv_stderr_ready():
            chunk = channel.recv_stderr(4096).decode("utf-8", errors="replace")
            err_buf += chunk
            scan_buf = (scan_buf + chunk)[-2048:]

        if regs and injections < max_injections and scan_buf:
            try:
                if any(r.search(scan_buf) for r in regs):
                    stdin.write(password + "\n")
                    stdin.flush()
                    injections += 1
                    scan_buf = ""
            except Exception:
                pass

        if time.time() - start > timeout:
            try:
                channel.close()
            except Exception:
                pass
            raise HTTPException(status_code=504, detail="Command timed out during interactive execution")

        time.sleep(0.05)

    exit_status = channel.recv_exit_status()
    out_buf_c = strip_ansi(out_buf)
    err_buf_c = strip_ansi(err_buf)
    return out_buf_c, err_buf_c, exit_status

# =================== Action logging ===================

def _node_label(server_meta: Optional[Dict[str, Any]]) -> str:
    if server_meta and server_meta.get("id"):
        return str(server_meta["id"])
    return f"{SSH_HOST}:{SSH_PORT}"

def _append_local_activity(server_meta: Optional[Dict[str, Any]], action: str, context: Dict[str, Any]):
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        parts = [f"{ts}", f"user={LOCAL_USER}", f"node={_node_label(server_meta)}", f"action={action}"]
        for k, v in (context or {}).items():
            if v is None:
                continue
            val = str(v).replace("\n", "\\n")
            if len(val) > 2000:
                val = val[:2000] + "…"
            parts.append(f"{k}={val}")
        line = " | ".join(parts) + "\n"
        with open(LOCAL_ACTIVITY_LOG, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass

def append_text_file(client: paramiko.SSHClient, path: str, content: str):
    sftp = client.open_sftp()
    try:
        try:
            with sftp.file(path, "a") as f:
                f.write(content)
        except FileNotFoundError:
            with sftp.file(path, "w") as f:
                f.write(content)
    finally:
        sftp.close()

def write_text_file(client: paramiko.SSHClient, path: str, content: str):
    sftp = client.open_sftp()
    try:
        with sftp.file(path, "w") as f:
            f.write(content)
    finally:
        sftp.close()

def read_json_file(client: paramiko.SSHClient, path: str) -> Optional[dict]:
    sftp = client.open_sftp()
    try:
        with sftp.file(path, "r") as f:
            data = f.read(256 * 1024).decode("utf-8", errors="replace")
            return json.loads(data)
    except FileNotFoundError:
        return None
    except Exception:
        return None
    finally:
        sftp.close()

def save_last_run(client: paramiko.SSHClient, base_dir: str, script_name: str):
    state_path = posixpath.join(base_dir, LAST_RUN_STATE)
    write_text_file(client, state_path, json.dumps({"script": script_name}, ensure_ascii=False))

def load_last_run(client: paramiko.SSHClient, base_dir: str) -> Optional[str]:
    state_path = posixpath.join(base_dir, LAST_RUN_STATE)
    data = read_json_file(client, state_path)
    return (data or {}).get("script")

def _rand_digits(n: int) -> str:
    if n <= 0:
        return ""
    from random import randint as rnd
    first = str(rnd(1, 9))
    if n == 1:
        return first
    rest = "".join(str(rnd(0, 9)) for _ in range(n - 1))
    return first + rest

def _norm_name(name: str) -> str:
    n = (name or "").lower()
    if n.endswith(".sh"):
        n = n[:-3]
    return re.sub(r"[^a-z0-9]", "", n)

def _append_activity_log(client: paramiko.SSHClient, base_dir: str, server_meta: Optional[Dict[str, Any]], action: str, context: Dict[str, Any]):
    try:
        _append_local_activity(server_meta, action, context)
    except Exception:
        pass
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        parts = [f"{ts}", f"user={LOCAL_USER}", f"node={_node_label(server_meta)}", f"action={action}"]
        for k, v in (context or {}).items():
            if v is None:
                continue
            val = str(v).replace("\n", "\\n")
            if len(val) > 2000:
                val = val[:2000] + "…"
            parts.append(f"{k}={val}")
        line = " | ".join(parts) + "\n"
        path = posixpath.join(base_dir, ACTIVITY_LOG_NAME)
        append_text_file(client, path, line)
    except Exception:
        pass

# =================== Scripts area endpoints ===================

@app.get("/health")
def health():
    return {
        "ok": True,
        "servers_file": os.path.abspath(os.getenv("DEPLOY_SERVERS_FILE", os.path.join(BASE_DIR, "servers.txt"))),
        "config_file": os.path.abspath(CONFIG_PATH),
        "local_activity_log": os.path.abspath(LOCAL_ACTIVITY_LOG),
    }

@app.get("/list_projects")
def list_projects(server_id: Optional[str] = Query(None)):
    client, server_meta = get_client_and_server_meta(server_id)
    try:
        sftp = client.open_sftp()
        try:
            base_dir = _root_base_for_server_meta(server_meta)
            entries = []
            try:
                for attr in sftp.listdir_attr(base_dir):
                    name = attr.filename
                    if name in (".", ".."):
                        continue
                    if stat.S_ISDIR(attr.st_mode):
                        entries.append(name)
                entries.sort()
                _append_local_activity(server_meta, "list_projects", {"count": len(entries), "base": base_dir})
                return {"projects": entries}
            except FileNotFoundError:
                _append_local_activity(server_meta, "list_projects_missing", {"base": base_dir})
                return {"projects": [], "note": f"Base dir not found: {base_dir}"}
        finally:
            sftp.close()
    finally:
        client.close()

@app.get("/list_directory")
def list_directory(
    subdir: str = Query(...),
    path: Optional[str] = Query(None),
    server_id: Optional[str] = Query(None)
):
    client, server_meta = get_client_and_server_meta(server_id)
    try:
        sftp = client.open_sftp()
        try:
            base_dir = base_for_subdir(subdir, sftp)
            target = base_dir if not path else ensure_within_base(base_dir, path)
            entries = sorted(sftp.listdir(target))
            _append_activity_log(client, base_dir, server_meta, "list_directory", {"path": target})
            return {"path": target, "files": entries}
        finally:
            sftp.close()
    finally:
        client.close()

class ScriptRequest(BaseModel):
    script_name: str
    subdir: str
    stdin_text: Optional[str] = None
    server_id: Optional[str] = None

@app.post("/run_script")
def run_script(request: ScriptRequest):
    if not request.script_name:
        raise HTTPException(status_code=400, detail="script_name is required")

    cfg = load_local_config()
    project = request.subdir
    script_name_in = posixpath.basename(request.script_name)
    rule = get_effective_rule(cfg, project, script_name_in)

    client, server_meta = get_client_and_server_meta(request.server_id)
    code = None
    try:
        sftp = client.open_sftp()
        try:
            base_dir = base_for_subdir(project, sftp)
        finally:
            sftp.close()

        script_path = ensure_within_base(base_dir, request.script_name)
        script_dir = posixpath.dirname(script_path)
        script_base = posixpath.basename(script_path)

        if rule.get("pre_write_input"):
            input_template = rule.get("input_template") or ""
            values: Dict[str, Any] = {}
            values_file = rule.get("input_values_file")
            if values_file:
                params_path = ensure_within_base(base_dir, values_file)
                vals = read_json_file(client, params_path)
                if isinstance(vals, dict):
                    values.update(vals)
            try:
                rendered = input_template.format(**{k: "" if v is None else v for k, v in values.items()})
            except KeyError as ke:
                raise HTTPException(status_code=400, detail=f"Missing input value for {ke}")
            rendered = rendered.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
            write_text_file(client, posixpath.join(base_dir, "input"), rendered)

        ctx: Dict[str, Any] = {"script": script_base}
        if isinstance(rule.get("vars"), dict):
            for k, v in rule["vars"].items():
                ctx[k] = v

        random_specs = rule.get("random_ids") or []
        if isinstance(random_specs, list):
            for spec in random_specs:
                try:
                    name = spec.get("name")
                    digits = int(spec.get("digits", 0))
                except Exception:
                    name, digits = None, 0
                if name and digits > 0:
                    ctx[name] = _rand_digits(digits)

        args_template = rule.get("args_template")
        if args_template:
            try:
                cmd_line = args_template.format(**ctx)
            except KeyError as ke:
                raise HTTPException(status_code=500, detail=f"args_template missing key: {ke}")
        else:
            cmd_line = f"./{posixpath.basename(script_path)}"

        env_vars = rule.get("env") or {}
        env_prefix = " ".join(f"{shlex.quote(k)}={shlex.quote(str(v))}" for k, v in env_vars.items())
        env_prefix = (env_prefix + " ") if env_prefix else ""
        inner = f"cd {shlex.quote(script_dir)} && {env_prefix}{cmd_line}"
        cmd = f"bash -lc {shlex.quote(inner)}"
        timeout = int(rule.get("timeout") or 900)

        auto_pass = rule.get("auto_password") or {}
        if bool(auto_pass.get("enabled")):
            password = str(auto_pass.get("value", ""))
            if not password:
                raise HTTPException(status_code=500, detail="auto_password enabled but no value provided")
            patterns = auto_pass.get("patterns") or [r"[Pp]assword:"]
            max_times = int(auto_pass.get("max_times") or 20)
            out, err, code = ssh_exec_interactive_autopass(
                client, cmd, timeout, password, patterns, max_injections=max_times, pre_stdin=request.stdin_text
            )
        else:
            norm_script = _norm_name(script_base)
            norm_proj = _norm_name(project)
            csv_trigger = (
                norm_script in {"csvolte", "csvoltedel"} or
                (norm_script == "sendrequest" and norm_proj == "csvoltedel")
            )
            if csv_trigger:
                ans = (request.stdin_text or "0").strip()
                if ans not in ("0", "1"):
                    ans = "0"
                patterns = [r"(?i)postpaid", r"(?i)enter.*postpaid", r"(?i)\benter\b.*\b1\b", r"(?i)choice", r":\s*$"]
                out, err, code = ssh_exec_interactive_autopass(
                    client, cmd, timeout=timeout, password=ans, prompt_patterns=patterns, max_injections=10, pre_stdin=ans
                )
            else:
                out, err, code = ssh_exec(client, cmd, timeout=timeout, stdin_data=request.stdin_text)

        try:
            save_last_run(client, base_dir, posixpath.basename(script_path))
        except Exception:
            pass

        post_tpl = rule.get("post_append_result_template")
        if post_tpl:
            try:
                line = post_tpl.format(**ctx)
            except KeyError as ke:
                line = f"APPEND_ERROR missing {ke}\n"
            defaults = cfg.get("defaults", {})
            candidates = rule.get("result_candidates") or defaults.get("result_candidates") or DEFAULT_CONFIG["defaults"]["result_candidates"]
            result_file = rule.get("result_file") or (candidates[0] if candidates else "results.txt")
            result_path = ensure_within_base(base_dir, result_file)
            append_text_file(client, result_path, line if line.endswith("\n") else line + "\n")

        _append_activity_log(client, base_dir, server_meta, "run_script", {"script": script_base, "exit": code})

        if code != 0:
            raise HTTPException(status_code=500, detail=err or f"Script exited with {code}")
        return {"output": strip_ansi(out), "error": strip_ansi(err)}
    finally:
        client.close()

class InputData(BaseModel):
    data: str
    subdir: str
    server_id: Optional[str] = None

@app.post("/write_input")
def write_input(request: InputData):
    cfg = load_local_config()
    project = request.subdir
    client, server_meta = get_client_and_server_meta(request.server_id)
    try:
        sftp = client.open_sftp()
        try:
            base_dir = base_for_subdir(project, sftp)
            remote_path = posixpath.join(base_dir, "input")
            text = request.data or ""
            text = text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
            with sftp.file(remote_path, "w") as f:
                f.write(text)
        finally:
            sftp.close()

        proj_settings = get_project_settings(cfg, project)
        post_cmd = proj_settings.get("post_write_input_command")
        if post_cmd:
            inner = f"cd {shlex.quote(base_dir)} && {post_cmd}"
            cmd = f"bash -lc {shlex.quote(inner)}"
            out, err, code = ssh_exec(client, cmd, timeout=60)
            if code != 0:
                _append_activity_log(client, base_dir, server_meta, "write_input", {"post_cmd_exit": code})
                raise HTTPException(status_code=500, detail=err or f"post_write_input_command exited with {code}")

        _append_activity_log(client, base_dir, server_meta, "write_input", {"bytes": len(request.data or "")})
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        client.close()

def _read_first_existing_file(
    client: paramiko.SSHClient,
    base_dir: str,
    candidates: List[str],
    max_bytes: int = 256 * 1024
) -> Tuple[str, str, bool, str]:
    sftp = client.open_sftp()
    try:
        for name in candidates:
            if not name or "/" in name or "\\" in name or ".." in name:
                continue
            path = ensure_within_base(base_dir, name)
            try:
                with sftp.file(path, "r") as f:
                    data = f.read(max_bytes + 1)
                    truncated = len(data) > max_bytes
                    if truncated:
                        data = data[:max_bytes]
                    content = data.decode("utf-8", errors="replace")
                    return name, path, truncated, strip_ansi(content)
            except FileNotFoundError:
                continue
        raise HTTPException(status_code=404, detail="File not found")
    finally:
        sftp.close()

@app.get("/hint")
def get_hint(
    subdir: str,
    filename: Optional[str] = Query(None),
    max_bytes: int = Query(256 * 1024, ge=1, le=5 * 1024 * 1024),
    server_id: Optional[str] = Query(None)
):
    cfg = load_local_config()
    client, server_meta = get_client_and_server_meta(server_id)
    try:
        sftp = client.open_sftp()
        try:
            base_dir = base_for_subdir(subdir, sftp)
        finally:
            sftp.close()

        if filename:
            candidates = [filename]
        else:
            defaults = cfg.get("defaults", {})
            base_candidates = defaults.get("hint_candidates") or DEFAULT_CONFIG["defaults"]["hint_candidates"]
            last_script = load_last_run(client, base_dir)
            if last_script:
                rule = get_effective_rule(cfg, subdir, last_script)
                if rule.get("hint_file"):
                    candidates = [rule["hint_file"]]
                elif rule.get("hint_candidates"):
                    candidates = [c for c in rule["hint_candidates"] if c]
                else:
                    candidates = [c for c in base_candidates if c]
            else:
                candidates = [c for c in base_candidates if c]

        name, path, truncated, content = _read_first_existing_file(client, base_dir, candidates, max_bytes)
        _append_activity_log(client, base_dir, server_meta, "hint", {"file": name, "truncated": truncated})
        return {"file": name, "path": path, "truncated": truncated, "content": content}
    finally:
        client.close()

@app.get("/result")
def get_result(
    subdir: str,
    filename: Optional[str] = Query(None),
    max_bytes: int = Query(512 * 1024, ge=1, le=8 * 1024 * 1024),
    tail: int = Query(0, ge=0, le=10000),
    server_id: Optional[str] = Query(None)
):
    cfg = load_local_config()
    client, server_meta = get_client_and_server_meta(server_id)
    try:
        sftp = client.open_sftp()
        try:
            base_dir = base_for_subdir(subdir, sftp)
        finally:
            sftp.close()

        if filename:
            candidates = [filename]
        else:
            defaults = cfg.get("defaults", {})
            base_candidates = defaults.get("result_candidates") or DEFAULT_CONFIG["defaults"]["result_candidates"]
            last_script = load_last_run(client, base_dir)
            if last_script:
                rule = get_effective_rule(cfg, subdir, last_script)
                if rule.get("result_file"):
                    candidates = [rule["result_file"]]
                elif rule.get("result_candidates"):
                    candidates = [c for c in rule["result_candidates"] if c]
                else:
                    candidates = [c for c in base_candidates if c]
            else:
                candidates = [c for c in base_candidates if c]

        name, path, truncated, content = _read_first_existing_file(client, base_dir, candidates, max_bytes)
        if tail and tail > 0:
            lines = content.splitlines()
            content = "\n".join(lines[-tail:])
        _append_activity_log(client, base_dir, server_meta, "result", {"file": name, "tail": tail, "truncated": truncated})
        return {"file": name, "path": path, "truncated": truncated, "content": content}
    finally:
        client.close()

class ClearRequest(BaseModel):
    subdir: str
    filename: Optional[str] = None
    server_id: Optional[str] = None

@app.post("/clear_result")
def clear_result(request: ClearRequest):
    cfg = load_local_config()
    client, server_meta = get_client_and_server_meta(request.server_id)
    try:
        sftp = client.open_sftp()
        try:
            base_dir = base_for_subdir(request.subdir, sftp)
        finally:
            sftp.close()

        if request.filename:
            target_name = request.filename
        else:
            defaults = cfg.get("defaults", {})
            base_candidates = defaults.get("result_candidates") or DEFAULT_CONFIG["defaults"]["result_candidates"]
            last_script = load_last_run(client, base_dir)
            target_name = None
            if last_script:
                rule = get_effective_rule(cfg, request.subdir, last_script)
                if rule.get("result_file"):
                    target_name = rule["result_file"]
            if not target_name:
                target_name = base_candidates[0] if base_candidates else "results.txt"

        target_path = ensure_within_base(base_dir, target_name)
        write_text_file(client, target_path, "")
        _append_activity_log(client, base_dir, server_meta, "clear_result", {"file": target_name})
        return {"success": True, "file": target_name, "path": target_path}
    except HTTPException:
        raise
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        client.close()

class ClearInputRequest(BaseModel):
    subdir: str
    filename: Optional[str] = None
    server_id: Optional[str] = None

@app.post("/clear_input")
def clear_input(request: ClearInputRequest):
    client, server_meta = get_client_and_server_meta(request.server_id)
    try:
        sftp = client.open_sftp()
        try:
            base_dir = base_for_subdir(request.subdir, sftp)
        finally:
            sftp.close()

        target_name = request.filename or "input"
        target_path = ensure_within_base(base_dir, target_name)
        write_text_file(client, target_path, "")
        _append_activity_log(client, base_dir, server_meta, "clear_input", {"file": target_name})
        return {"success": True, "file": target_name, "path": target_path}
    except HTTPException:
        raise
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        client.close()

# =================== DEPLOY (servers.txt-driven) ===================

DEPLOY_SERVERS_FILE = os.getenv("DEPLOY_SERVERS_FILE", os.path.join(BASE_DIR, "servers.txt"))
DEPLOY_ALLOWED_BASE = os.getenv("DEPLOY_ALLOWED_BASE", ROOT_BASE_DIR)

def _parse_server_line(line: str) -> Optional[Dict[str, Any]]:
    if not line:
        return None
    core = line.split("#", 1)[0].strip()
    if not core:
        return None
    parts = core.split()
    host_part = parts[0]
    username = SSH_USERNAME
    port = 22
    if ":" in host_part:
        host_only, port_str = host_part.split(":", 1)
        host = host_only.strip()
        try:
            port = int(port_str.strip())
        except Exception:
            port = 22
    else:
        host = host_part.strip()
    if len(parts) >= 2:
        username = parts[1].strip() or SSH_USERNAME
    if len(parts) >= 3:
        try:
            port = int(parts[2].strip())
        except Exception:
            pass
    if not host:
        return None
    sid = f"{host}:{port}"
    label = f"{host}:{port}"
    return {"id": sid, "label": label, "host": host, "port": port, "username": username}

def _load_servers_from_file() -> List[Dict[str, Any]]:
    servers: List[Dict[str, Any]] = []
    try:
        with open(DEPLOY_SERVERS_FILE, "r", encoding="utf-8") as f:
            for raw in f:
                item = _parse_server_line(raw.strip())
                if item:
                    servers.append(item)
    except FileNotFoundError:
        return []
    except Exception:
        return servers
    return servers

def _find_deploy_server(server_id: str) -> Optional[Dict[str, Any]]:
    for s in _load_servers_from_file():
        if s.get("id") == server_id:
            return s
    return None

@app.get("/deploy/servers")
def deploy_servers():
    servers = _load_servers_from_file()
    _append_local_activity(None, "deploy_servers", {"count": len(servers)})
    return {
        "servers": [
            {"id": s.get("id"), "label": s.get("label") or s.get("id"), "host": s.get("host")}
            for s in servers
        ]
    }

@app.get("/deploy/test_connection")
def deploy_test_connection(server_id: str = Query(...)):
    server = _find_deploy_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Unknown server_id")
    client = ssh_client_for_server(server)
    try:
        out, err, code = ssh_exec(client, "bash -lc 'echo OK'", timeout=10)
        ok = (code == 0 and "OK" in (out or ""))
        _append_local_activity(server, "deploy_test_connection", {"ok": ok, "exit": code})
        return {"ok": ok, "output": out, "error": err}
    finally:
        client.close()

# ===== Config files list/backup =====

CFG_SRC1 = "/home/kpsa39/provMbl/runtime/conf"
CFG_SRC2 = "/home/kpsa39/provMbl/reference/conf"
CFG_DST  = "/home/bullkpsa_G2R0C0/backups/test"

CFG_FILES = [
    {"dir": CFG_SRC1, "name": "kpsa.cfg"},
    {"dir": CFG_SRC1, "name": "cartsConfigFile.cfg"},
    {"dir": CFG_SRC2, "name": "mapping.cfg"},
]

def _stamp_filename(name: str, ts: str) -> str:
    if not name:
        return name
    if name.startswith("."):
        return f"{name}_{ts}"
    if "." in name:
        base, ext = name.rsplit(".", 1)
        if not base:
            return f"{name}_{ts}"
        return f"{base}_{ts}.{ext}"
    return f"{name}_{ts}"

def _safe_exact_join(dir_path: str, name: str) -> str:
    if not name or "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=400, detail=f"Invalid filename: {name!r}")
    return posixpath.join(dir_path, name)

@app.get("/deploy/list_cfg_sources")
def deploy_list_cfg_sources(server_id: str = Query(...)):
    server = _find_deploy_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Unknown server_id")
    client = ssh_client_for_server(server)
    try:
        out_ts, err_ts, code_ts = ssh_exec(client, "bash -lc 'date +%Y%m%d_%H%M%S'", timeout=10)
        ts = (out_ts or "").strip() if code_ts == 0 else time.strftime("%Y%m%d_%H%M%S")

        sftp = client.open_sftp()
        try:
            required_map: Dict[str, List[str]] = {}
            for item in CFG_FILES:
                required_map.setdefault(item["dir"], []).append(item["name"])

            sources = []
            for dir_path, req_names in required_map.items():
                present = []
                missing = []
                for nm in req_names:
                    p = _safe_exact_join(dir_path, nm)
                    try:
                        st = sftp.stat(p)
                        if stat.S_ISREG(st.st_mode):
                            present.append(nm)
                        else:
                            missing.append(nm)
                    except FileNotFoundError:
                        missing.append(nm)
                sources.append({
                    "dir": dir_path, "required": req_names,
                    "present": present, "missing": missing
                })

            _append_local_activity(server, "deploy_list_cfg_sources", {"server_time": ts})
            return {"server_time": ts, "sources": sources}
        finally:
            sftp.close()
    finally:
        client.close()

class DeployCfgBackupRequest(BaseModel):
    server_id: str

@app.post("/deploy/backup_cfg")
def deploy_backup_cfg(req: DeployCfgBackupRequest):
    server = _find_deploy_server(req.server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Unknown server_id")

    client = ssh_client_for_server(server)
    try:
        out_ts, err_ts, code_ts = ssh_exec(client, "bash -lc 'date +%Y%m%d_%H%M%S'", timeout=10)
        ts = (out_ts or "").strip() if code_ts == 0 else time.strftime("%Y%m%d_%H%M%S")

        inner_mkdir = f"mkdir -p {shlex.quote(CFG_DST)}"
        cmd_mkdir = f"bash -lc {shlex.quote(inner_mkdir)}"
        mkdir_out, mkdir_err, mkdir_code = ssh_exec(client, cmd_mkdir, timeout=10)
        if mkdir_code != 0:
            _append_local_activity(server, "deploy_backup_cfg", {"dest_dir": CFG_DST, "exit": mkdir_code})
            raise HTTPException(status_code=500, detail=f"Failed to create destination dir: {mkdir_err or mkdir_out}")

        copies: List[Dict[str, Any]] = []
        all_ok = True

        for item in CFG_FILES:
            src_path = _safe_exact_join(item["dir"], item["name"])
            dst_name = _stamp_filename(item["name"], ts)
            dst_path = _safe_exact_join(CFG_DST, dst_name)

            inner = (
                f"test -f {shlex.quote(src_path)} "
                f"&& cp -p {shlex.quote(src_path)} {shlex.quote(dst_path)} "
                f"|| (echo 'Source file not found: {src_path}' 1>&2; false)"
            )
            cmd = f"bash -lc {shlex.quote(inner)}"
            out, err, code = ssh_exec(client, cmd, timeout=60)

            ok = (code == 0)
            all_ok = all_ok and ok
            copies.append({
                "src": src_path, "dst": dst_path, "ok": ok,
                "output": out, "error": err
            })

        _append_local_activity(server, "deploy_backup_cfg", {"dest_dir": CFG_DST, "success": all_ok})
        return {"success": all_ok, "server_time": ts, "dest_dir": CFG_DST, "copies": copies}
    finally:
        client.close()

# =================== Shipments (SFTP list + SSE deploy/rollback/import) ===================

DEPLOY_SHIP_DIR = os.getenv("DEPLOY_SHIP_DIR")
DEPLOY_SHIP_DAYS_DEFAULT = int(os.getenv("DEPLOY_SHIP_DAYS", "30"))

def _shipments_dir_for_server(server: Dict[str, Any]) -> str:
    if DEPLOY_SHIP_DIR:
        return DEPLOY_SHIP_DIR
    remote_user = server.get("username") or SSH_USERNAME
    return f"/home/{remote_user}"

@app.get("/deploy/shipments")
def deploy_shipments(
    server_id: str = Query(..., description="ID from /deploy/servers"),
    days: int = Query(DEPLOY_SHIP_DAYS_DEFAULT, ge=0, le=365, description="Look-back window in days (0=all)")
):
    server = _find_deploy_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Unknown server_id")
    ship_dir = _shipments_dir_for_server(server)
    client = ssh_client_for_server(server)
    try:
        sftp = client.open_sftp()
        try:
            try:
                st = sftp.stat(ship_dir)
                if not stat.S_ISDIR(st.st_mode):
                    raise HTTPException(status_code=404, detail=f"Shipments path is not a directory: {ship_dir}")
            except FileNotFoundError:
                raise HTTPException(status_code=404, detail=f"Shipments directory not found: {ship_dir}")
            now = time.time()
            items = []
            scanned = 0
            zip_seen = 0
            kept = 0
            for attr in sftp.listdir_attr(ship_dir):
                scanned += 1
                name = attr.filename
                if not name or name.startswith("."): continue
                if not stat.S_ISREG(attr.st_mode): continue
                if not name.lower().endswith(".zip"): continue
                zip_seen += 1
                mtime = int(getattr(attr, "st_mtime", 0) or 0)
                if days > 0 and (now - float(mtime)) > days * 86400:
                    continue
                size = getattr(attr, "st_size", None)
                items.append({
                    "name": name,
                    "path": posixpath.join(ship_dir, name),
                    "size": int(size) if isinstance(size, int) else None,
                    "mtime_ts": int(mtime),
                    "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime)) if mtime else None,
                })
                kept += 1
            items.sort(key=lambda x: x.get("mtime_ts", 0), reverse=True)
            _append_local_activity(server, "deploy_shipments", {"dir": ship_dir, "days": days, "kept": kept})
            return {"shipments": items, "debug": {"dir": ship_dir, "days": days, "scanned": scanned, "zip_seen": zip_seen, "kept": kept}}
        finally:
            sftp.close()
    finally:
        client.close()

def _sse_line(text: str) -> str:
    text = strip_ansi(text or "").replace("\r", "")
    lines = text.split("\n")
    if not lines:
        return "data: \n\n"
    return "".join(f"data: {ln}\n" for ln in lines) + "\n"

def _safe_zip_name(name: str) -> str:
    if not name or "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=400, detail="Invalid shipment name")
    if not name.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Shipment must be a .zip file")
    return name

def _stream_deploy_shipment(server: Dict[str, Any], name: str, timeout_sec: int = 7200):
    client = ssh_client_for_server(server)
    ship_dir = _shipments_dir_for_server(server)
    base = name[:-4]
    start_ts = time.time()
    exit_code = None
    try:
        _append_local_activity(server, "deploy_shipment", {"name": name, "stage": "begin"})
        yield _sse_line(f"== Deploying shipment: {name} ==")
        inner = (
            f"set -e\n"
            f"cd {shlex.quote(ship_dir)}\n"
            f"echo 'Unzipping {name}...'\n"
            f"unzip -o {shlex.quote(name)}\n"
            f"echo 'Entering {base} ...'\n"
            f"cd {shlex.quote(base)}\n"
            f"echo 'Running patch_PNode.ksh (auto-yes)...'\n"
            f"chmod +x patch_PNode.ksh || true\n"
            f"yes Y | ./patch_PNode.ksh\n"
            f"echo '== Deployment finished for {name} =='"
        )
        cmd = f"bash -lc {shlex.quote(inner)}"
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True, timeout=timeout_sec)
        channel = stdout.channel
        while True:
            while channel.recv_ready():
                yield _sse_line(channel.recv(4096).decode("utf-8", errors="replace"))
            while channel.recv_stderr_ready():
                yield _sse_line("ERR: " + channel.recv_stderr(4096).decode("utf-8", errors="replace"))
            if channel.exit_status_ready():
                while channel.recv_ready():
                    yield _sse_line(channel.recv(4096).decode("utf-8", errors="replace"))
                while channel.recv_stderr_ready():
                    yield _sse_line("ERR: " + channel.recv_stderr(4096).decode("utf-8", errors="replace"))
                exit_code = channel.recv_exit_status()
                yield _sse_line(f"[exit {exit_code}]")
                break
            if time.time() - start_ts > timeout_sec:
                try: channel.close()
                except Exception: pass
                yield _sse_line("[timeout]")
                exit_code = -1
                break
            time.sleep(0.05)
    except Exception as e:
        yield _sse_line(f"[error] {e}")
        exit_code = -2
    finally:
        try: client.close()
        except Exception: pass
        _append_local_activity(server, "deploy_shipment", {"name": name, "stage": "end", "exit": exit_code})

@app.get("/deploy/deploy_shipment")
def deploy_deploy_shipment(server_id: str = Query(...), name: str = Query(...)):
    server = _find_deploy_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Unknown server_id")
    safe_name = _safe_zip_name(name)
    headers = {"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"}
    return StreamingResponse(_stream_deploy_shipment(server, safe_name), media_type="text/event-stream", headers=headers)

# Rollback SSE
def _stream_rollback_shipment(server: Dict[str, Any], name: str, timeout_sec: int = 7200):
    client = ssh_client_for_server(server)
    ship_dir = _shipments_dir_for_server(server)
    base = name[:-4]
    start_ts = time.time()
    exit_code = None
    try:
        _append_local_activity(server, "rollback_shipment", {"name": name, "stage": "begin"})
        yield _sse_line(f"== Rolling back shipment: {name} ==")
        inner = (
            f"set -e\n"
            f"cd {shlex.quote(ship_dir)}\n"
            f"echo 'Entering {base} ...'\n"
            f"test -d {shlex.quote(base)} || (echo 'ERR: directory not found: {base}' 1>&2; exit 2)\n"
            f"cd {shlex.quote(base)}\n"
            f"echo 'Running patch_PNode.ksh -R (auto-yes)...'\n"
            f"chmod +x patch_PNode.ksh || true\n"
            f"yes Y | ./patch_PNode.ksh -R\n"
            f"echo '== Rollback finished for {name} =='"
        )
        cmd = f"bash -lc {shlex.quote(inner)}"
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True, timeout=timeout_sec)
        channel = stdout.channel
        while True:
            while channel.recv_ready():
                yield _sse_line(channel.recv(4096).decode("utf-8", errors="replace"))
            while channel.recv_stderr_ready():
                yield _sse_line("ERR: " + channel.recv_stderr(4096).decode("utf-8", errors="replace"))
            if channel.exit_status_ready():
                while channel.recv_ready():
                    yield _sse_line(channel.recv(4096).decode("utf-8", errors="replace"))
                while channel.recv_stderr_ready():
                    yield _sse_line("ERR: " + channel.recv_stderr(4096).decode("utf-8", errors="replace"))
                exit_code = channel.recv_exit_status()
                yield _sse_line(f"[exit {exit_code}]")
                break
            if time.time() - start_ts > timeout_sec:
                try: channel.close()
                except Exception: pass
                yield _sse_line("[timeout]")
                exit_code = -1
                break
            time.sleep(0.05)
    except Exception as e:
        yield _sse_line(f"[error] {e}")
        exit_code = -2
    finally:
        try: client.close()
        except Exception: pass
        _append_local_activity(server, "rollback_shipment", {"name": name, "stage": "end", "exit": exit_code})

@app.get("/deploy/rollback_shipment")
def deploy_rollback_shipment(server_id: str = Query(...), name: str = Query(...)):
    server = _find_deploy_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Unknown server_id")
    safe_name = _safe_zip_name(name)
    headers = {"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"}
    return StreamingResponse(_stream_rollback_shipment(server, safe_name), media_type="text/event-stream", headers=headers)

# Import latest shipment (parallel to all targets)

IMPORT_SOURCE_HOST = os.getenv("IMPORT_SOURCE_HOST", "10.11.116.40")
IMPORT_SOURCE_PORT = int(os.getenv("IMPORT_SOURCE_PORT", "22"))
IMPORT_SOURCE_DIR = os.getenv("IMPORT_SOURCE_DIR", "/home/bullkpsa_G2R0C0/ATOS_Delivery")
IMPORT_DEST_DIR = os.getenv("IMPORT_DEST_DIR", "/home/bullkpsa_G2R0C0")

def _source_server_meta() -> Dict[str, Any]:
    return {
        "id": f"{IMPORT_SOURCE_HOST}:{IMPORT_SOURCE_PORT}",
        "label": f"{IMPORT_SOURCE_HOST}:{IMPORT_SOURCE_PORT}",
        "host": IMPORT_SOURCE_HOST,
        "port": IMPORT_SOURCE_PORT,
        "username": SSH_USERNAME,
    }

def _progress_bar(pct: int, width: int = 26) -> str:
    pct = max(0, min(100, int(pct)))
    fill = int(pct * width / 100)
    return "[" + "#" * fill + "." * (width - fill) + f"] {pct:3d}%"

def _stream_import_latest(timeout_sec: int = 4 * 3600, chunk_size: int = 1024 * 1024):
    src_srv = _source_server_meta()
    start_ts = time.time()
    yield _sse_line(f"== Import (parallel): source {src_srv['id']} dir={IMPORT_SOURCE_DIR} ==")

    # 1) Find newest .zip on source (single scan)
    try:
        src_scan_client = ssh_client_for_server(src_srv)
    except HTTPException as e:
        yield _sse_line(f"[error] Cannot connect to source: {e.detail}")
        return

    latest_name = None
    latest_mtime = 0
    latest_size = 0
    try:
        sftp = src_scan_client.open_sftp()
        try:
            try:
                st = sftp.stat(IMPORT_SOURCE_DIR)
                if not stat.S_ISDIR(st.st_mode):
                    yield _sse_line(f"[error] Source path is not a directory: {IMPORT_SOURCE_DIR}")
                    return
            except FileNotFoundError:
                yield _sse_line(f"[error] Source directory not found: {IMPORT_SOURCE_DIR}")
                return
            for attr in sftp.listdir_attr(IMPORT_SOURCE_DIR):
                name = attr.filename
                if not name or name.startswith("."): continue
                if not stat.S_ISREG(attr.st_mode): continue
                if not name.lower().endswith(".zip"): continue
                mtime = int(getattr(attr, "st_mtime", 0) or 0)
                if mtime >= latest_mtime:
                    latest_mtime = mtime
                    latest_name = name
                    latest_size = int(getattr(attr, "st_size", 0) or 0)
            if not latest_name:
                yield _sse_line("[error] No .zip found in source directory")
                return
            yield _sse_line(f"Found: {latest_name} — {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(latest_mtime))} — {latest_size} bytes")
        finally:
            sftp.close()
    except Exception as e:
        yield _sse_line(f"[error] Failed to scan source: {e}")
        try: src_scan_client.close()
        except Exception: pass
        return
    finally:
        try: src_scan_client.close()
        except Exception: pass

    # 2) Parallel copy to each target
    targets = _load_servers_from_file()
    if not targets:
        yield _sse_line("[error] servers.txt is empty or missing")
        return

    q: "queue.Queue[tuple]" = queue.Queue()
    total_targets = len(targets)

    def worker(target: Dict[str, Any]):
        host_label = target.get("id") or f"{target.get('host')}:{target.get('port')}"
        q.put(("info", host_label, f"start copy {latest_name}"))
        try:
            # Fresh connections per thread (source + target)
            src_client = ssh_client_for_server(_source_server_meta())
            tgt_client = ssh_client_for_server(target)
        except HTTPException as e:
            q.put(("error", host_label, f"connect failed: {e.detail}"))
            return
        try:
            # Ensure dest dir
            inner = f"mkdir -p {shlex.quote(IMPORT_DEST_DIR)}"
            cmd = f"bash -lc {shlex.quote(inner)}"
            _, mkerr, mkcode = ssh_exec(tgt_client, cmd, timeout=30)
            if mkcode != 0:
                q.put(("error", host_label, f"mkdir failed: {mkerr}"))
                return

            src_sftp = src_client.open_sftp()
            tgt_sftp = tgt_client.open_sftp()
            try:
                src_file_path = posixpath.join(IMPORT_SOURCE_DIR, latest_name)
                dest_tmp = posixpath.join(IMPORT_DEST_DIR, f".{latest_name}.part")
                dest_final = posixpath.join(IMPORT_DEST_DIR, latest_name)

                with src_sftp.file(src_file_path, "rb") as fin, tgt_sftp.file(dest_tmp, "wb") as fout:
                    copied = 0
                    last_pct = -1
                    while True:
                        buf = fin.read(chunk_size)
                        if not buf:
                            break
                        fout.write(buf)
                        copied += len(buf)
                        if latest_size > 0:
                            pct = int(copied * 100 / latest_size)
                            if pct != last_pct:
                                q.put(("progress", host_label, copied, latest_size, pct))
                                last_pct = pct
                    try:
                        fout.flush()
                    except Exception:
                        pass

                # Atomic rename to final
                try:
                    try:
                        tgt_sftp.remove(dest_final)
                    except IOError:
                        pass
                    tgt_sftp.rename(dest_tmp, dest_final)
                except Exception as e:
                    q.put(("error", host_label, f"finalize rename failed: {e}"))
                    return

                q.put(("done", host_label, dest_final))
            finally:
                try: src_sftp.close()
                except Exception: pass
                try: tgt_sftp.close()
                except Exception: pass
        except Exception as e:
            q.put(("error", host_label, f"{e}"))
        finally:
            try: src_client.close()
            except Exception: pass
            try: tgt_client.close()
            except Exception: pass

    max_workers = min(8, total_targets) if total_targets > 0 else 0
    executor = ThreadPoolExecutor(max_workers=max_workers or 1)
    try:
        for t in targets:
            executor.submit(worker, t)

        # Drain queue and stream SSE until all targets completed (done/error)
        done_hosts = set()
        last_heartbeat = time.time()
        while len(done_hosts) < total_targets:
            try:
                msg = q.get(timeout=0.3)
            except queue.Empty:
                # keep-alive heartbeat every ~3s
                if time.time() - last_heartbeat > 3:
                    yield _sse_line("...")
                    last_heartbeat = time.time()
                continue

            kind = msg[0]
            host = msg[1]
            if kind == "progress":
                _, _, copied, total, pct = msg
                bar = _progress_bar(pct)
                yield _sse_line(f"[{host}] {bar}  {copied}/{total} bytes")
            elif kind == "done":
                _, _, path = msg
                if host not in done_hosts:
                    done_hosts.add(host)
                yield _sse_line(f"[{host}] Done -> {path}")
            elif kind == "error":
                _, _, err = msg
                if host not in done_hosts:
                    done_hosts.add(host)
                yield _sse_line(f"[{host}] [error] {err}")
            elif kind == "info":
                _, _, info = msg
                yield _sse_line(f"[{host}] {info}")

    finally:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    elapsed = int(time.time() - start_ts)
    yield _sse_line(f"== Import complete (parallel) in {elapsed}s ==")

@app.get("/deploy/import_latest_shipment")
def deploy_import_latest_shipment():
    headers = {"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"}
    return StreamingResponse(_stream_import_latest(), media_type="text/event-stream", headers=headers)

# =================== DEPLOY: Node control (SSE) ===================

def _stream_ssh_sse(server: Dict[str, Any], action: str, command: str, timeout_sec: int = 1800):
    client = ssh_client_for_server(server)
    start_ts = time.time()
    exit_code = None
    try:
        _append_local_activity(server, "deploy_node_cmd", {"action": action, "stage": "begin"})
        yield _sse_line(f"Executing: {command}")
        cmd = f"bash -lc {shlex.quote(command)}"
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True, timeout=timeout_sec)
        channel = stdout.channel
        while True:
            while channel.recv_ready():
                yield _sse_line(channel.recv(4096).decode("utf-8", errors="replace"))
            while channel.recv_stderr_ready():
                yield _sse_line("ERR: " + channel.recv_stderr(4096).decode("utf-8", errors="replace"))
            if channel.exit_status_ready():
                while channel.recv_ready():
                    yield _sse_line(channel.recv(4096).decode("utf-8", errors="replace"))
                while channel.recv_stderr_ready():
                    yield _sse_line("ERR: " + channel.recv_stderr(4096).decode("utf-8", errors="replace"))
                exit_code = channel.recv_exit_status()
                yield _sse_line(f"[exit {exit_code}]")
                break
            if time.time() - start_ts > timeout_sec:
                try: channel.close()
                except Exception: pass
                yield _sse_line("[timeout]")
                exit_code = -1
                break
            time.sleep(0.05)
    except Exception as e:
        yield _sse_line(f"[error] {e}")
        exit_code = -2
    finally:
        try: client.close()
        except Exception: pass
        _append_local_activity(server, "deploy_node_cmd", {"action": action, "stage": "end", "exit": exit_code})

def _build_kpsa_script(cmdline: str) -> str:
    return (
        "set -e\n"
        "if [ -f ~/.bash_profile ]; then . ~/.bash_profile; fi\n"
        "if [ -f ~/.profile ]; then . ~/.profile; fi\n"
        "if ! command -v kpsa.ksh >/dev/null 2>&1; then\n"
        "  if [ -x \"$HOME/provMbl/bin/kpsa.ksh\" ]; then export PATH=\"$HOME/provMbl/bin:$PATH\"; fi\n"
        "  if [ -x \"/home/kpsa39/provMbl/bin/kpsa.ksh\" ]; then export PATH=\"/home/kpsa39/provMbl/bin:$PATH\"; fi\n"
        "fi\n"
        "echo \"Using PATH: $PATH\"\n"
        f"echo \"Running: {cmdline}\"\n"
        f"{cmdline}\n"
    )

@app.get("/deploy/node_cmd")
def deploy_node_cmd(server_id: str = Query(...), action: str = Query(...)):
    server = _find_deploy_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Unknown server_id")
    action = (action or "").strip().lower()
    if action not in {"start", "stop", "status"}:
        raise HTTPException(status_code=400, detail="Invalid action; use start | stop | status")
    cmd_map = {"start": "kpsa.ksh -start", "stop": "kpsa.ksh -stop force", "status": "kpsa.ksh -status"}
    base_cmd = cmd_map[action]
    script = _build_kpsa_script(base_cmd)
    headers = {"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"}
    return StreamingResponse(_stream_ssh_sse(server, action, script), media_type="text/event-stream", headers=headers)

# =================== Shared helpers: server selection for scripts area ===================

def get_client_and_server_meta(server_id: Optional[str]) -> Tuple[paramiko.SSHClient, Optional[Dict[str, Any]]]:
    if server_id:
        server = _find_deploy_server(server_id)
        if not server:
            raise HTTPException(status_code=404, detail="Unknown server_id")
        client = ssh_client_for_server(server)
        return client, server
    return ssh_client(), None

# =================== Startup info ===================

@app.on_event("startup")
def _print_paths():
    print(f"[INFO] Using servers file: {os.path.abspath(DEPLOY_SERVERS_FILE)}")
    print(f"[INFO] Using config file: {os.path.abspath(CONFIG_PATH)}")
    print(f"[INFO] Local activity log: {os.path.abspath(LOCAL_ACTIVITY_LOG)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)
