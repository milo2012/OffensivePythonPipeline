import os
import subprocess
import threading
import uuid
import json
import urllib.request
import zipfile
import re
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, Response, stream_with_context

app = Flask(__name__)

BUILDS_DIR = Path("/builds")
BUILDS_DIR.mkdir(exist_ok=True)

jobs = {}
jobs_lock = threading.Lock()

PRESETS = {
    "certipy": {
        "label": "Certipy",
        "author": "ly4k",
        "pip": "certipy-ad",
        "build_type": "pip",
        "entry": "from certipy.entry import main\nimport sys\nif __name__ == '__main__': sys.exit(main())",
        "name": "certipy",
        "versions": [
            {"version": "latest", "label": "Latest"},
            {"version": "5.1.0", "label": "5.1.0", "verified": True},
            {"version": "4.8.2", "label": "4.8.2", "verified": True},
        ],
        "hidden_imports": [
            "certipy", "certipy.entry", "certipy.commands",
            "certipy.commands.account", "certipy.commands.auth",
            "certipy.commands.ca", "certipy.commands.cert",
            "certipy.commands.find", "certipy.commands.forge",
            "certipy.commands.parsers", "certipy.commands.relay",
            "certipy.commands.req", "certipy.commands.shadow",
            "certipy.commands.template",
            "certipy.lib", "certipy.lib.certificate",
            "certipy.lib.constants", "certipy.lib.errors",
            "certipy.lib.logger", "certipy.lib.target",
            "impacket", "impacket.examples",
            "impacket.examples.ntlmrelayx",
            "impacket.examples.ntlmrelayx.attacks",
            "impacket.examples.ntlmrelayx.clients",
            "impacket.examples.ntlmrelayx.servers",
            "impacket.examples.ntlmrelayx.utils",
            "impacket.examples.ntlmrelayx.attacks.httprelayclient",
            "impacket.examples.ntlmrelayx.attacks.ldaprelayclient",
            "impacket.examples.ntlmrelayx.attacks.mssqlrelayclient",
            "impacket.examples.ntlmrelayx.attacks.smbrelayclient",
            "impacket.examples.ntlmrelayx.clients.httprelayclient",
            "impacket.examples.ntlmrelayx.clients.imaprelaylient",
            "impacket.examples.ntlmrelayx.clients.ldaprelayclient",
            "impacket.examples.ntlmrelayx.clients.mssqlrelayclient",
            "impacket.examples.ntlmrelayx.clients.smbrelayclient",
            "impacket.examples.ntlmrelayx.servers.httprelayserver",
            "impacket.examples.ntlmrelayx.servers.smbrelayserver",
            "impacket.examples.ntlmrelayx.servers.wcfrelayserver",
            "impacket.examples.ntlmrelayx.utils.config",
            "impacket.examples.ntlmrelayx.utils.targetsutils",
            "argcomplete", "cryptography",
            "cryptography.hazmat", "cryptography.hazmat.primitives",
            "cryptography.hazmat.primitives.asymmetric",
            "pkg_resources", "setuptools",
        ],
        "collect_all": ["certipy", "impacket"],
    },
    "netexec": {
        "label": "NetExec",
        "author": "Pennyw0rth",
        "build_type": "git",
        "repo": "https://github.com/Pennyw0rth/NetExec.git",
        "spec": "netexec.spec",
        "name": "nxc",
        "versions": [
            {"version": "latest", "label": "Latest (main)"},
            {"version": "v1.5.1", "label": "v1.5.1", "verified": True},
            {"version": "v1.4.0", "label": "v1.4.0", "verified": True},
        ],
    },
    "impacket": {
        "label": "Impacket",
        "author": "fortra",
        "build_type": "git",
        "repo": "https://github.com/fortra/impacket.git",
        "spec": None,
        "name": "impacket",
        "versions": [
            {"version": "latest", "label": "Latest (master)"},
            {"version": "impacket_0_13_0", "label": "0.13.0", "verified": True},
        ],
    },
    "responder": {
        "label": "Responder",
        "author": "lgandx",
        "build_type": "git",
        "repo": "https://github.com/lgandx/Responder.git",
        "spec": None,
        "name": "responder",
        "versions": [
            {"version": "latest", "label": "Latest (master)"},
        ],
        "hidden_imports": [
            "asyncio", "ssl", "socketserver", "netifaces",
            "aioquic", "aioquic.asyncio", "aioquic.quic",
            "aioquic.quic.configuration", "aioquic.quic.connection",
            "cryptography", "cryptography.hazmat",
            "cryptography.hazmat.primitives",
            "cryptography.hazmat.primitives.asymmetric",
            "pkg_resources", "setuptools",
        ],
    },
    "pcredz": {
        "label": "PCredz",
        "author": "lgandx",
        "build_type": "git",
        "repo": "https://github.com/lgandx/PCredz.git",
        "spec": None,
        "name": "Pcredz",
        "versions": [
            {"version": "latest", "label": "Latest (master)"},
        ],
        "hidden_imports": [
            "pcapy", "datetime", "argparse", "logging",
            "struct", "binascii", "base64", "re",
        ],
    },
    "smbmap": {
        "label": "SMBMap",
        "author": "ShawnDEvans",
        "pip": "smbmap",
        "build_type": "pip",
        "entry": "from smbmap.smbmap import main\nimport sys\nif __name__ == '__main__': sys.exit(main())",
        "name": "smbmap",
        "versions": [
            {"version": "latest", "label": "Latest"},
            {"version": "1.10.8", "label": "1.10.8", "verified": True},
        ],
        "hidden_imports": [
            "smbmap", "smbmap.smbmap",
            "impacket", "impacket.examples",
            "impacket.smbconnection", "impacket.smbserver",
            "impacket.nmb", "impacket.smb3structs",
            "impacket.dcerpc", "impacket.dcerpc.v5",
            "impacket.dcerpc.v5.transport",
            "impacket.dcerpc.v5.scmr",
            "impacket.dcerpc.v5.dcomrt",
            "impacket.dcerpc.v5.dcom",
            "impacket.dcerpc.v5.dcom.wmi",
            "impacket.dcerpc.v5.dtypes",
            "impacket.examples.logger",
            "pyasn1", "pyasn1.type", "pyasn1.codec",
            "Crypto", "Crypto.Cipher",
            "termcolor", "configparser",
            "pkg_resources", "setuptools",
        ],
        "collect_all": ["smbmap", "impacket"],
    },    
}


def run_build(job_id, preset_key, version, custom_pip, custom_entry, custom_name):
    def log(msg):
        with jobs_lock:
            jobs[job_id]["log"].append(msg)

    try:
        workdir = BUILDS_DIR / job_id
        workdir.mkdir(parents=True, exist_ok=True)

        def run(cmd, cwd=None):
            log(f"$ {' '.join(str(c) for c in cmd)}")
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=cwd
            )
            for line in proc.stdout:
                log(line.rstrip())
            proc.wait()
            if proc.returncode != 0:
                raise RuntimeError(f"Command failed with code {proc.returncode}")

        if preset_key and preset_key in PRESETS:
            cfg = PRESETS[preset_key]
            build_type = cfg.get("build_type", "pip")

            if build_type == "git":
                if preset_key == "impacket":
                    _run_impacket_build(cfg, version, workdir, run, log)
                elif preset_key == "responder":
                    _run_responder_build(cfg, version, workdir, run, log)
                elif preset_key == "pcredz":
                    _run_pcredz_build(cfg, version, workdir, run, log)
                else:
                    _run_git_build(cfg, version, workdir, run, log)
            else:
                _run_pip_build(cfg, version, workdir, run, log)

        elif custom_pip and custom_entry and custom_name:
            cfg = {
                "pip": custom_pip,
                "entry": custom_entry,
                "name": custom_name,
                "hidden_imports": [],
                "collect_all": [],
            }
            _run_pip_build(cfg, "latest", workdir, run, log)
        else:
            raise ValueError("Invalid build configuration")

    except Exception as e:
        log(f"==> ERROR: {e}")
        with jobs_lock:
            jobs[job_id]["status"] = "error"


def _run_pip_build(cfg, version, workdir, run, log):
    job_id = workdir.name
    pip_install = cfg["pip"] if not version or version == "latest" else f"{cfg['pip']}=={version}"
    log(f"==> Installing {pip_install} ...")
    run(["python3.12", "-m", "pip", "install", "--upgrade", pip_install])

    entry_path = workdir / "entry.py"
    entry_path.write_text(cfg["entry"])
    log(f"==> Entry point written to {entry_path}")

    binary_name = cfg["name"]
    dist_dir = workdir / "dist"
    build_dir = workdir / "build"

    cmd = [
        "python3.12", "-m", "PyInstaller",
        "--onefile",
        f"--name={binary_name}",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        f"--specpath={workdir}",
        "--clean",
    ]
    for hi in cfg.get("hidden_imports", []):
        cmd += [f"--hidden-import={hi}"]
    for ca in cfg.get("collect_all", []):
        cmd += [f"--collect-all={ca}"]
    cmd.append(str(entry_path))

    log("==> Starting PyInstaller build ...")
    run(cmd)
    _finalize_build(cfg["name"], workdir / "dist", job_id, log)


def _run_git_build(cfg, version, workdir, run, log):
    job_id = workdir.name
    repo_dir = workdir / "repo"

    log(f"==> Cloning {cfg['repo']} ...")
    run(["git", "clone", cfg["repo"], str(repo_dir)])

    if version and version != "latest":
        log(f"==> Checking out {version} ...")
        run(["git", "checkout", version], cwd=str(repo_dir))

    log("==> Installing dependencies ...")
    run(["python3.12", "-m", "pip", "install", "pyinstaller", "."], cwd=str(repo_dir))

    dist_dir = workdir / "dist"
    build_dir = workdir / "build"
    spec_file = cfg.get("spec")

    log("==> Starting PyInstaller build ...")
    if spec_file and (repo_dir / spec_file).exists():
        log(f"==> Using spec file: {spec_file}")
        cmd = [
            "python3.12", "-m", "PyInstaller",
            f"--distpath={dist_dir}",
            f"--workpath={build_dir}",
            "--clean",
            spec_file,
        ]
        run(cmd, cwd=str(repo_dir))
    else:
        raise FileNotFoundError(f"Spec file '{spec_file}' not found in repo")

    _finalize_build(cfg["name"], dist_dir, job_id, log)

def _run_pcredz_build(cfg, version, workdir, run, log):
    job_id = workdir.name
    repo_dir = workdir / "repo"

    log(f"==> Cloning {cfg['repo']} ...")
    run(["git", "clone", "--depth=1", cfg["repo"], str(repo_dir)])

    if version and version != "latest":
        log(f"==> Checking out {version} ...")
        run(["git", "fetch", "--tags"], cwd=str(repo_dir))
        run(["git", "checkout", version], cwd=str(repo_dir))

    log("==> Installing pcapy-ng (requires libpcap-dev) ...")
    run(["python3.12", "-m", "pip", "install", "pcapy-ng", "pyinstaller"])

    # PCredz's main script has no .py extension — rename it so PyInstaller handles it
    script_src = repo_dir / "Pcredz"
    script_dst = repo_dir / "Pcredz.py"
    if not script_src.exists():
        raise FileNotFoundError("Pcredz script not found in repo")

    script_dst.write_text(script_src.read_text())
    log("==> Copied Pcredz -> Pcredz.py for PyInstaller")

    # Create logs dir that PCredz expects at runtime
    (repo_dir / "logs").mkdir(exist_ok=True)

    dist_dir = workdir / "dist"
    dist_dir.mkdir(exist_ok=True)
    build_dir = workdir / "build"

    hidden_imports = cfg.get("hidden_imports", [])

    cmd = [
        "python3.12", "-m", "PyInstaller",
        "--onefile",
        "--name=Pcredz",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        f"--specpath={workdir}",
        "--clean",
        f"--paths={repo_dir}",
    ]
    for hi in hidden_imports:
        cmd += [f"--hidden-import={hi}"]
    cmd.append(str(script_dst))

    log("==> Building Pcredz binary ...")
    run(cmd)

    binary_path = dist_dir / "Pcredz"
    if not binary_path.exists():
        raise FileNotFoundError("Pcredz binary not found after build")

    # Zip binary + logs dir placeholder
    zip_path = workdir / "pcredz.zip"
    log("==> Packaging binary ...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(binary_path, "pcredz/Pcredz")
        # Include empty logs dir
        zf.writestr("pcredz/logs/.gitkeep", "")
        usage = (
            "# PCredz Binary\n\n"
            "  unzip pcredz.zip\n"
            "  cd pcredz/\n"
            "  chmod +x Pcredz\n\n"
            "  # Live capture:\n"
            "  sudo ./Pcredz -i eth0\n\n"
            "  # From pcap file:\n"
            "  sudo ./Pcredz -f capture.pcap\n\n"
            "NOTE: Requires libpcap on the target (apt install libpcap-dev)\n"
            "Credentials are logged to ./logs/\n"
        )
        zf.writestr("pcredz/USAGE.txt", usage)

    log("==> Pcredz build complete!")

    with jobs_lock:
        jobs[job_id]["status"] = "done"
        jobs[job_id]["binary"] = str(zip_path)
        jobs[job_id]["binary_name"] = "pcredz.zip"

    _glibc_check(str(binary_path), log)

def _run_impacket_build(cfg, version, workdir, run, log):
    job_id = workdir.name
    repo_dir = workdir / "repo"

    log(f"==> Cloning {cfg['repo']} ...")
    run(["git", "clone", "--depth=1", cfg["repo"], str(repo_dir)])

    if version and version != "latest":
        log(f"==> Checking out {version} ...")
        run(["git", "fetch", "--tags"], cwd=str(repo_dir))
        run(["git", "checkout", version], cwd=str(repo_dir))

    log("==> Installing impacket and dependencies ...")
    run(["python3.12", "-m", "pip", "install", "."], cwd=str(repo_dir))

    examples_dir = repo_dir / "examples"
    scripts = sorted([
        f for f in examples_dir.glob("*.py")
        if f.name not in ("__init__.py",)
    ])
    log(f"==> Found {len(scripts)} example scripts to compile")

    dist_dir = workdir / "dist"
    dist_dir.mkdir(exist_ok=True)
    build_dir = workdir / "build"

    failed = []
    succeeded = []

    for script in scripts:
        tool_name = script.stem
        log(f"==> Building {tool_name} ...")
        try:
            cmd = [
                "python3.12", "-m", "PyInstaller",
                "--onefile",
                f"--name={tool_name}",
                f"--distpath={dist_dir}",
                f"--workpath={build_dir / tool_name}",
                f"--specpath={workdir}",
                "--clean",
                "--hidden-import=impacket",
                "--hidden-import=impacket.examples",
                "--hidden-import=impacket.examples.ntlmrelayx",
                "--hidden-import=impacket.examples.ntlmrelayx.attacks",
                "--hidden-import=impacket.examples.ntlmrelayx.clients",
                "--hidden-import=impacket.examples.ntlmrelayx.servers",
                "--hidden-import=impacket.examples.ntlmrelayx.utils",
                "--collect-all=impacket",
                "--hidden-import=pkg_resources",
                "--hidden-import=setuptools",
                str(script),
            ]
            run(cmd)
            succeeded.append(tool_name)
        except Exception as e:
            log(f"==> WARNING: {tool_name} failed: {e}")
            failed.append(tool_name)

    if not succeeded:
        raise RuntimeError("All impacket tools failed to build")

    zip_path = workdir / "impacket-binaries.zip"
    log(f"==> Zipping {len(succeeded)} binaries ...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for tool_name in succeeded:
            binary = dist_dir / tool_name
            if binary.exists():
                zf.write(binary, tool_name)

    log(f"==> Built {len(succeeded)} tools successfully")
    if failed:
        log(f"==> WARNING: {len(failed)} tools failed: {', '.join(failed)}")

    with jobs_lock:
        jobs[job_id]["status"] = "done"
        jobs[job_id]["binary"] = str(zip_path)
        jobs[job_id]["binary_name"] = "impacket-binaries.zip"

    _glibc_check(str(dist_dir / succeeded[0]), log)


def _patch_responder_settings(repo_dir, log):
    """
    Patch settings.py so ResponderPATH resolves correctly inside a PyInstaller bundle.

    Original line 31:
        self.ResponderPATH = os.path.dirname(__file__)

    When frozen, __file__ for a bundled module points into sys._MEIPASS (the temp
    extraction dir), which is correct — BUT only if Responder.conf is also extracted
    there via --add-data. We patch the line to use sys._MEIPASS when frozen, and the
    directory of the real executable (sys.executable) as fallback so the binary can
    also find Responder.conf placed next to it on disk.
    """
    settings_path = repo_dir / "settings.py"
    if not settings_path.exists():
        log("==> WARNING: settings.py not found, skipping patch")
        return

    original = settings_path.read_text()

    old_line = "self.ResponderPATH = os.path.dirname(__file__)"
    new_lines = (
        "if getattr(sys, 'frozen', False):\n"
        "\t\t\t# PyInstaller frozen binary: --add-data extracts files to sys._MEIPASS\n"
        "\t\t\tself.ResponderPATH = sys._MEIPASS\n"
        "\t\t\t# Also copy conf to exe dir on first run so logs/db go there\n"
        "\t\t\t_exe_dir = os.path.dirname(sys.executable)\n"
        "\t\t\t_conf_dst = os.path.join(_exe_dir, 'Responder.conf')\n"
        "\t\t\tif not os.path.exists(_conf_dst):\n"
        "\t\t\t\timport shutil\n"
        "\t\t\t\tshutil.copy(os.path.join(self.ResponderPATH, 'Responder.conf'), _conf_dst)\n"
        "\t\t\tfor _d in ['certs', 'files']:\n"
        "\t\t\t\t_src = os.path.join(self.ResponderPATH, _d)\n"
        "\t\t\t\t_dst = os.path.join(_exe_dir, _d)\n"
        "\t\t\t\tif os.path.exists(_src) and not os.path.exists(_dst):\n"
        "\t\t\t\t\timport shutil\n"
        "\t\t\t\t\tshutil.copytree(_src, _dst)\n"
        "\t\t\tself.ResponderPATH = _exe_dir\n"
        "\t\telse:\n"
        "\t\t\tself.ResponderPATH = os.path.dirname(__file__)"
    )

    if old_line not in original:
        log("==> WARNING: Could not find patch target in settings.py — skipping patch")
        return

    # Also ensure sys is imported at top of settings.py
    patched = original.replace(old_line, new_lines)
    if "import sys" not in patched:
        patched = "import sys\n" + patched

    settings_path.write_text(patched)
    log("==> Patched settings.py: ResponderPATH now resolves correctly when frozen")


def _run_responder_build(cfg, version, workdir, run, log):
    job_id = workdir.name
    repo_dir = workdir / "repo"

    log(f"==> Cloning {cfg['repo']} ...")
    run(["git", "clone", "--depth=1", cfg["repo"], str(repo_dir)])

    if version and version != "latest":
        log(f"==> Checking out {version} ...")
        run(["git", "fetch", "--tags"], cwd=str(repo_dir))
        run(["git", "checkout", version], cwd=str(repo_dir))

    log("==> Installing Responder dependencies ...")
    run(["python3.12", "-m", "pip", "install",
         "netifaces", "aioquic", "cryptography", "setuptools", "pyinstaller"])

    # Patch settings.py BEFORE building
    _patch_responder_settings(repo_dir, log)

    dist_dir = workdir / "dist"
    dist_dir.mkdir(exist_ok=True)
    build_dir = workdir / "build"

    # Only build the main scripts — skip internal modules
    skip = {"setup.py", "odict.py"}
    scripts_to_build = sorted([
        f for f in repo_dir.glob("*.py")
        if f.name not in skip
    ])
    log(f"==> Found {len(scripts_to_build)} scripts to build: {[s.name for s in scripts_to_build]}")

    hidden_imports = cfg.get("hidden_imports", [])
    failed = []
    succeeded = []

    # --add-data embeds conf+certs+files into sys._MEIPASS at runtime
    conf_src = repo_dir / "Responder.conf"
    certs_src = repo_dir / "certs"
    files_src = repo_dir / "files"

    add_data_args = []
    if conf_src.exists():
        add_data_args += [f"--add-data={conf_src}:."]
    if certs_src.exists():
        add_data_args += [f"--add-data={certs_src}:certs"]
    if files_src.exists():
        add_data_args += [f"--add-data={files_src}:files"]

    for script in scripts_to_build:
        tool_name = script.stem
        log(f"==> Building {tool_name} ...")
        try:
            cmd = [
                "python3.12", "-m", "PyInstaller",
                "--onefile",
                f"--name={tool_name}",
                f"--distpath={dist_dir}",
                f"--workpath={build_dir / tool_name}",
                f"--specpath={workdir}",
                "--clean",
                f"--paths={repo_dir}",
            ]
            for hi in hidden_imports:
                cmd += [f"--hidden-import={hi}"]
            cmd += add_data_args
            cmd.append(str(script))
            run(cmd)
            succeeded.append(tool_name)
        except Exception as e:
            log(f"==> WARNING: {tool_name} failed: {e}")
            failed.append(tool_name)

    if not succeeded:
        raise RuntimeError("All Responder tools failed to build")

    # Build zip: binaries only — conf/certs/files are extracted automatically
    # on first run by the patched settings.py
    zip_path = workdir / "responder-binaries.zip"
    log(f"==> Packaging {len(succeeded)} binaries ...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for tool_name in succeeded:
            binary = dist_dir / tool_name
            if binary.exists():
                zf.write(binary, f"responder/{tool_name}")

        # Also include Responder.conf alongside binaries as a convenience
        if conf_src.exists():
            zf.write(conf_src, "responder/Responder.conf")
        if certs_src.exists():
            for f in certs_src.rglob("*"):
                if f.is_file():
                    zf.write(f, f"responder/certs/{f.relative_to(certs_src)}")
        if files_src.exists():
            for f in files_src.rglob("*"):
                if f.is_file():
                    zf.write(f, f"responder/files/{f.relative_to(files_src)}")

        usage = (
            "# Responder Binaries\n\n"
            "Extract and run — conf/certs/files are auto-extracted on first run:\n\n"
            "  unzip responder-binaries.zip\n"
            "  cd responder/\n"
            "  chmod +x Responder RunFinger DHCP\n"
            "  sudo ./Responder -I eth0 -v\n\n"
            "On first run, Responder.conf and certs/ are written next to the binary.\n"
            "Logs and Responder.db are also created in the same directory.\n"
        )
        zf.writestr("responder/USAGE.txt", usage)

    log(f"==> Built {len(succeeded)} tools: {', '.join(succeeded)}")
    if failed:
        log(f"==> WARNING: Failed to build: {', '.join(failed)}")
    log(f"==> Zip ready: {zip_path}")

    with jobs_lock:
        jobs[job_id]["status"] = "done"
        jobs[job_id]["binary"] = str(zip_path)
        jobs[job_id]["binary_name"] = "responder-binaries.zip"

    if succeeded:
        _glibc_check(str(dist_dir / succeeded[0]), log)


def _glibc_check(binary_path, log):
    result = subprocess.run(
        ["objdump", "-T", binary_path],
        capture_output=True, text=True
    )
    versions = re.findall(r'GLIBC_(\d+\.\d+)', result.stdout)
    if versions:
        from packaging.version import Version
        max_ver = max(versions, key=lambda v: Version(v))
        log(f"==> Max GLIBC required: {max_ver}")
        if Version(max_ver) > Version("2.28"):
            log(f"==> WARNING: Binary requires GLIBC {max_ver} but target only has 2.28!")
        else:
            log(f"==> OK: Binary is compatible with GLIBC 2.28 targets")


def _finalize_build(binary_name, dist_dir, job_id, log):
    binary_path = Path(dist_dir) / binary_name
    if not binary_path.exists():
        matches = list(Path(dist_dir).rglob(binary_name))
        if matches:
            binary_path = matches[0]
        else:
            raise FileNotFoundError(f"Binary '{binary_name}' not found in {dist_dir}")

    log(f"==> Build complete! Binary: {binary_path}")

    with jobs_lock:
        jobs[job_id]["status"] = "done"
        jobs[job_id]["binary"] = str(binary_path)
        jobs[job_id]["binary_name"] = binary_name

    _glibc_check(str(binary_path), log)


@app.route("/")
def index():
    return render_template("index.html", presets=PRESETS)


@app.route("/build", methods=["POST"])
def start_build():
    job_id = str(uuid.uuid4())
    data = request.json

    with jobs_lock:
        jobs[job_id] = {"log": [], "status": "running", "binary": None}

    t = threading.Thread(
        target=run_build,
        args=(
            job_id,
            data.get("preset"),
            data.get("version"),
            data.get("custom_pip"),
            data.get("custom_entry"),
            data.get("custom_name"),
        ),
        daemon=True,
    )
    t.start()
    return jsonify({"job_id": job_id})


@app.route("/log/<job_id>")
def stream_log(job_id):
    def generate():
        sent = 0
        while True:
            with jobs_lock:
                job = jobs.get(job_id)
            if not job:
                yield f"data: {json.dumps({'line': 'Job not found', 'done': True})}\n\n"
                return
            lines = job["log"]
            while sent < len(lines):
                yield f"data: {json.dumps({'line': lines[sent]})}\n\n"
                sent += 1
            if job["status"] in ("done", "error"):
                yield f"data: {json.dumps({'done': True, 'status': job['status']})}\n\n"
                return
            import time; time.sleep(0.5)

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/download/<job_id>")
def download(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job or job["status"] != "done":
        return "Build not ready", 404
    binary_path = job["binary"]
    binary_name = job.get("binary_name", "binary")
    return send_file(binary_path, as_attachment=True, download_name=binary_name)


@app.route("/versions/<preset_key>")
def get_versions(preset_key):
    if preset_key not in PRESETS:
        return jsonify({"error": "Unknown preset"}), 404

    cfg = PRESETS[preset_key]
    verified = {
        v["version"]: v.get("verified", False)
        for v in cfg.get("versions", [])
        if v["version"] not in ("latest", "latest (main)", "latest (master)")
    }

    if cfg.get("build_type") == "git":
        try:
            repo = cfg["repo"].replace("https://github.com/", "").replace(".git", "")
            url = f"https://api.github.com/repos/{repo}/tags?per_page=50"
            req = urllib.request.Request(url, headers={"User-Agent": "pybuilder/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                tags = json.loads(resp.read())

            versions = [{"version": "latest", "label": "Latest", "verified": False}]
            for t in tags:
                name = t["name"]
                if name.startswith("impacket_"):
                    label = name.replace("impacket_", "").replace("_", ".")
                else:
                    label = name
                versions.append({
                    "version": name,
                    "label": label,
                    "verified": verified.get(name, False),
                })
            return jsonify({"versions": versions})
        except Exception as e:
            return jsonify({
                "versions": cfg.get("versions", [{"version": "latest", "label": "Latest", "verified": False}]),
                "error": str(e)
            })

    pip_pkg = cfg["pip"]
    try:
        url = f"https://pypi.org/pypi/{pip_pkg}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "pybuilder/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        releases = sorted(
            data["releases"].keys(),
            key=lambda v: [int(x) for x in v.split(".") if x.isdigit()],
            reverse=True
        )

        versions = [{"version": "latest", "label": "Latest", "verified": False}]
        for r in releases:
            if not data["releases"][r]:
                continue
            versions.append({
                "version": r,
                "label": r,
                "verified": verified.get(r, False),
            })
        return jsonify({"versions": versions})

    except Exception as e:
        return jsonify({
            "versions": cfg.get("versions", [{"version": "latest", "label": "Latest", "verified": False}]),
            "error": str(e)
        })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)