#! /usr/bin/env python3
import hashlib
import json
import signal
import subprocess
from os import environ, execvp, makedirs, path
from pathlib import Path
from shutil import rmtree
from sys import exit

import yaml
from box import Box
from jinja2 import Environment, FileSystemLoader

LIVE = path.join("/", "etc", "letsencrypt", "live")
DOMAIN_HASHES = path.join(LIVE, "domain_hashes.json")
SMNRP_CONFIG = path.join("/", "etc", "nginx", "conf.d", "smnrp.conf")


# Helper functions
def _stable_signature(domain_name: str, domain) -> str:
    # Sort SANs so ordering in YAML doesn't change the hash
    sans_norm = sorted(str(s).strip() for s in (domain.get("sans", [])))
    return f"{domain_name}|{json.dumps(sans_norm, separators=(',', ':'), ensure_ascii=False)}"


def compute_domain_hash(domain_name: str, domain) -> str:
    sig = _stable_signature(domain_name, domain)
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()


def store_domain_hash(
    store_path: str,
    domain_name: str,
    domain,
) -> str:
    store_path = Path(store_path)
    h = compute_domain_hash(domain_name, domain)

    # Load existing store (or start empty)
    if store_path.exists():
        data = json.loads(store_path.read_text(encoding="utf-8") or "{}")
        if not isinstance(data, dict):
            raise TypeError("Hash store file is not a JSON object/dict.")
    else:
        data = {}

    data[domain_name] = h

    # Atomic write
    store_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = store_path.with_suffix(store_path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(store_path)

    return h


def get_domain_hash(store_path: str, domain_name: str) -> str | None:
    store_path = Path(store_path)
    if not store_path.exists():
        return None

    data = json.loads(store_path.read_text(encoding="utf-8") or "{}")
    if not isinstance(data, dict):
        raise TypeError("Hash store file is not a JSON object/dict.")

    val = data.get(domain_name)
    return str(val) if val is not None else None


# END helper functions

if "SMNRP" not in environ:
    print("SMNRP environment variable not set")
    exit(1)
else:
    cfg = Box(yaml.safe_load(environ["SMNRP"]))
    # with open("smnrp.yml") as config:
    #     cfg = Box(yaml.safe_load(config))

env = Environment(loader=FileSystemLoader("templates"), trim_blocks=True, lstrip_blocks=True)
template = env.get_template("smnrp.conf.j2")

for domain_name, domain in cfg.domains.items():
    # Generate self-signed certificates if needed
    if "cert" in domain and domain.cert == "self-signed":
        live = f"{LIVE}/{domain_name}"
        makedirs(live, exist_ok=True)
        csr_config = path.join(live, "csr.conf")
        if not path.exists(csr_config):
            template = env.get_template("csr.conf.j2")
            with open(csr_config, "w") as csr:
                csr.write(template.render(domain_name=domain_name, domain=domain))

        cmd = [
            "openssl",
            "req",
            "-x509",
            "-nodes",
            "-days",
            "3650",
            "-newkey",
            "rsa:4096",
            "-keyout",
            path.join(live, "privkey.pem"),
            "-out",
            path.join(live, "fullchain.pem"),
            "-config",
            path.join(live, "csr.conf"),
        ]
        subprocess.run(cmd, check=True)
    else:
        # Hash management of domain configs
        new_hash = compute_domain_hash(domain_name, domain)
        old_hash = get_domain_hash(DOMAIN_HASHES, domain_name)
        if new_hash != old_hash or not path.isfile(path.join(LIVE, domain_name, "fullchain.pem")):
            store_domain_hash(DOMAIN_HASHES, domain_name, domain)
            # Prepare for cert request
            with open(SMNRP_CONFIG, "w") as config:
                config.write(template.render(certrequest=True, domains=cfg.domains))
            nginx_syntax_check = subprocess.run(["nginx", "-t"], check=True)
            if nginx_syntax_check.returncode != 0:
                print("!!! Configuration issues !!!")
                exit(2)
            else:
                # Start intermediate nginx
                nginx = subprocess.Popen(
                    [
                        "nginx",
                        "-g",
                        "daemon off;",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if nginx.poll() is not None:
                    out, err = nginx.communicate(timeout=1)
                    raise RuntimeError(f"nginx failed to start.\nstdout:\n{out}\nstderr:\n{err}")
            try:
                cmd = [
                    "certbot",
                    "certonly",
                    "--webroot",
                    "-w",
                    "/var/www/certbot",
                    "--register-unsafely-without-email",
                    "-d",
                    f"{domain_name},{','.join(domain.sans)}",
                    "--rsa-key-size",
                    "4096",
                    "--agree-tos",
                    "--force-renewal",
                ]
                subprocess.run(cmd, check=True)

                # Kill nginx
                if nginx.poll() is None:
                    nginx.send_signal(signal.SIGTERM)
                try:
                    nginx.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    nginx.kill()
                    nginx.wait()
            except subprocess.CalledProcessError:
                print(f"!!! Cannot request certificate for domain '{domain_name}' !!!")
                if path.isdir(path.join(LIVE, domain_name)):
                    rmtree(path.join(LIVE, domain_name))
                exit(3)

# Create final nginx config and replace entrypoint with nginx
with open(SMNRP_CONFIG, "w") as config:
    config.write(template.render(certrequest=False, domains=cfg.domains))

# Check nginx config syntax, exit in case of errors
nginx_syntax_check = subprocess.run(["nginx", "-t"], check=True)
if nginx_syntax_check.returncode != 0:
    print("!!! Configuration issues !!!")
    exit(2)
else:
    execvp(
        "nginx",
        ["nginx", "-g", "daemon off;"],
    )
