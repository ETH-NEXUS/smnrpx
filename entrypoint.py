#! /usr/bin/env python3
import contextlib
import hashlib
import json
import re
import signal
import subprocess
from os import environ, execvp, fork, makedirs, path, remove, symlink
from pathlib import Path
from shutil import copy, rmtree
from sys import argv, exit
from time import sleep

import yamale
import yaml
from box import Box
from jinja2 import Environment, FileSystemLoader
from yamale.yamale_error import YamaleError

LIVE = path.join("/", "etc", "letsencrypt", "live")
DOMAIN_HASHES = path.join(LIVE, "domain_hashes.json")
SMNRP_CONFIG = path.join(path.sep, "run", "configs", "smnrp.yml")
NGINX_DOT_CONF = path.join("/", "etc", "nginx", "nginx.conf")
NGINX_CONFIG_BASE = path.join("/", "etc", "nginx", "conf.d")
SMNRP_NGINX_CONFIG = path.join(NGINX_CONFIG_BASE, "smnrp.conf")
CERT_RENEW_TIMEOUT = 24 * 60 * 60
DOMAIN_REGEX = re.compile(r"^(?:(?P<sub>.+)\.)?(?P<main>[^.]+\.[^.]+)$")
ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


DEFAULTS = {
    "server_tokens": "off",
    "proxy_buffer_size": "32k",
    "client_max_body_size": "1m",
    "client_body_buffer_size": "1k",
    "allow_tls1_2": False,
    "disable_ocsp_stapling": False,
}


# Helper functions
def _stable_signature(domain_name: str, domain) -> str:
    # Sort SANs so ordering in YAML doesn't change the hash
    sans_norm = sorted(str(s).strip() for s in (domain.get("sans", [])))
    return f"{domain_name}|{domain.cert if 'cert' in domain else ''}|{json.dumps(sans_norm, separators=(',', ':'), ensure_ascii=False)}"


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


def populate_if_not_exists(domain_name: str, filename: str):
    web_root = path.join(path.sep, "web_root", domain_name)
    makedirs(web_root, exist_ok=True)
    src_dir = path.join(path.sep, "usr", "share", "nginx")
    if not path.isfile(path.join(web_root, filename)):
        copy(path.join(src_dir, filename), path.join(web_root, filename))


def print_context(filename: str, line_no: int, context=5):
    with open(filename) as f:
        lines = f.readlines()

    start = max(0, line_no - context - 1)
    end = min(len(lines), line_no + context)

    for i in range(start, end):
        prefix = ">" if i == line_no - 1 else " "
        print(f"{prefix}{i + 1:5}: {lines[i].rstrip()}")


def check_nginx_syntax():
    # Check nginx config syntax, exit in case of errors
    nginx = subprocess.Popen(
        ["nginx", "-t"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if nginx.wait() != 0:
        out, err = nginx.communicate(timeout=1)
        print("❌ nginx configuration issues:")
        print(f"{out}\n{err}")
        pattern = re.compile(rf"{re.escape(SMNRP_NGINX_CONFIG)}:(\d+)")
        for line in err.splitlines():
            m = pattern.search(line)
            if m:
                print_context(SMNRP_NGINX_CONFIG, int(m.group(1)))
                break
        exit(2)
    else:
        print("✅ nginx configuration is ok")


def check_smnrp_config(config):
    try:
        schema = yamale.make_schema("/smnrp_schema.yml")
        config = yamale.make_data(content=yaml.safe_dump(config))
        yamale.validate(schema, config)
        print("✅ SMNRP configuration is valid")
    except YamaleError as e:
        print("❌ SMNRP configuration validation failed, findings:")
        for result in e.results:
            for error in result.errors:
                print("-", error)
        exit(4)


def cert_renew():
    print("🪪 Starting cerbot renewal process")
    while True:
        sleep(CERT_RENEW_TIMEOUT)
        print("🪪 Renew certificates")
        if path.isfile(path.join(path.sep, "tmp", "letsencrypt.log")):
            remove(path.join(path.sep, "tmp", "letsencrypt.log"))
        certbot = subprocess.Popen(
            [
                "certbot",
                "renew",
                "--non-interactive",
                "--log",
                "/tmp",
                "--deploy-hook",
                "nginx -s reload",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        out, err = certbot.communicate(timeout=1)
        print(f"{out}")
        if certbot.poll() != 0:
            print(f"{err}")
            print("❌ Certificate renewal failed.")


def create_dhparams():
    dhparams_file = path.join(path.sep, "etc", "letsencrypt", "dhparams.pem")
    if not path.isfile(dhparams_file):
        print("⏳ Creating dhparams file. This will take a few minutes, be patient 🧘.")
        p_dhparam = subprocess.Popen(
            ["openssl", "dhparam", "-out", dhparams_file, "4096"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if p_dhparam.wait() != 0:
            out, err = p_dhparam.communicate(timeout=1)
            print(f"❌ Could not create dhparams file: {out}\n{err}")
            exit(6)


def apply_defaults(cfg: Box) -> Box:
    for k, v in DEFAULTS.items():
        if k not in cfg:
            cfg[k] = v
    return cfg


def get_grouped_domains(cfg: Box):
    # Go through the domains and collect all main-domain related sans
    # to avoid multiple requests per main domain, which will be rejected
    # by Let's Encrypt
    cert_domain_specs = []
    grouped_domains = {}
    for domain_name, domain in cfg.domains.items():
        if "cert" not in domain or domain.cert == "letsencrypt":
            cert_domain_specs.append({"domain": domain_name, "type": "vhost"})
            if "sans" in domain:
                for san in domain.sans:
                    cert_domain_specs.append({"domain": san, "type": "san"})

    for domain_spec in cert_domain_specs:
        match = DOMAIN_REGEX.match(domain_spec["domain"])
        if not match:
            print(f"⚠️ '{domain_spec['domain']}' is not a correct domain name, ignoring")
            continue

        main = match.group("main")

        if main not in grouped_domains:
            grouped_domains[main] = []

        grouped_domains[main].append(domain_spec)

    return grouped_domains


def prepare_nginx_for_cert_request(cfg: Box):
    with open(SMNRP_NGINX_CONFIG, "w") as config:
        template = env.get_template("smnrp.conf.j2")
        config.write(template.render(certrequest=True, domains=cfg.domains))
    check_nginx_syntax()
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
    return nginx


def kill_nginx(nginx):
    # Kill nginx
    if nginx.poll() is None:
        nginx.send_signal(signal.SIGTERM)
    try:
        nginx.wait(timeout=3)
    except subprocess.TimeoutExpired:
        nginx.kill()
        nginx.wait()


def handle_cert_request(grouped_domains: dict):
    for _, domain_specs in grouped_domains.items():
        for domain_spec in domain_specs:
            # find the first vhost
            if domain_spec["type"] == "vhost":
                vhost = domain_spec["domain"]
                sans = [
                    domain_spec["domain"]
                    for domain_spec in domain_specs
                    if domain_spec["domain"] != vhost
                ]
                break
        print(f"✅ requesting certificate from letsencrypt for domain '{vhost}'")
        try:
            cmd = [
                "certbot",
                "certonly",
                "--webroot",
                "-w",
                "/var/www/certbot",
                "--register-unsafely-without-email",
                "-d",
                f"{vhost},{','.join(sans)}",
                "--rsa-key-size",
                "4096",
                "--agree-tos",
                "--force-renewal",
                "--log",
                "/tmp",
            ]
            subprocess.run(cmd, check=True)
            # if certificate was requested create sym links for the other vhosts
            for domain_spec in domain_specs:
                if domain_spec["type"] == "vhost" and domain_spec["domain"] != vhost:
                    if path.isdir(path.join(LIVE, vhost)):
                        with contextlib.suppress(FileExistsError):
                            symlink(path.join(LIVE, vhost), path.join(LIVE, domain_spec["domain"]))
        except subprocess.CalledProcessError as err:
            print(f"❌ Cannot request certificate for domain '{vhost}'")
            print(err)
            if path.isdir(path.join(LIVE, vhost)):
                rmtree(path.join(LIVE, vhost))
            exit(3)


def expand_env_vars(value):
    if isinstance(value, str):
        return ENV_VAR_PATTERN.sub(lambda m: environ.get(m.group(1), m.group(0)), value)
    elif isinstance(value, dict):
        return {k: expand_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [expand_env_vars(v) for v in value]
    return value


# END helper functions

print("🚀 Start SMNRP 🚀")

# Get config from SMNRP environment variable if set
if "SMNRP" in environ:
    SMNRP_CONFIG = path.join(path.sep, "tmp", "smnrp.yml")
    env_config = environ.get("SMNRP")
    if env_config:
        out_path = Path(SMNRP_CONFIG)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(env_config, encoding="utf-8")
        print("✅ Take config from environment variable 'SMNRP'")
else:
    # Check if config is there
    if not path.isfile(SMNRP_CONFIG):
        print("❌ SMNRP config is missing")
        print("👉 Please configure the config in docker-compose.yml:")
        print("configs:")
        print("  smnrp:")
        print("    file: ./smnrp.yml")
        print("services:")
        print("  ws:")
        print("    configs:")
        print("      - source: smnrp")
        print(f"        target: {SMNRP_CONFIG}")
        exit(1)

with open(SMNRP_CONFIG) as config_file:
    config = expand_env_vars(yaml.safe_load(config_file))
    check_smnrp_config(config)
    cfg = Box(config)

# Apply config defaults to be most secure
cfg = apply_defaults(cfg)

# Create templating environment
env = Environment(loader=FileSystemLoader("templates"), trim_blocks=True, lstrip_blocks=True)

# Remove default nginx config
if path.isfile(path.join(NGINX_CONFIG_BASE, "default.conf")):
    remove(path.join(NGINX_CONFIG_BASE, "default.conf"))

create_dhparams()

nginx = prepare_nginx_for_cert_request(cfg)
handle_cert_request(get_grouped_domains(cfg))
kill_nginx(nginx)

for domain_name, domain in cfg.domains.items():
    # Copy over default files
    populate_if_not_exists(domain_name, "index.html")
    populate_if_not_exists(domain_name, "favicon.ico")
    populate_if_not_exists(domain_name, "background.jpg")

    # Prepare authentication
    if "locations" in domain:
        for _location in domain.locations:
            _, location = next(iter(_location.items()))
            if "auth" in location:
                auth_config = path.join(
                    NGINX_CONFIG_BASE,
                    f".auth_{domain_name}{location.uri.replace(path.sep, '_')}",
                )
                if path.isfile(auth_config):
                    remove(auth_config)
                for auth in location.auth:
                    try:
                        print(
                            f"👤 enable authentication on '{domain_name}{location.uri}' for user '{auth.user}', {auth_config}"
                        )
                        subprocess.run(
                            [
                                "htpasswd",
                                "-b",
                                *([] if path.isfile(auth_config) else ["-c"]),
                                auth_config,
                                auth.user,
                                auth.password,
                            ],
                            check=True,
                        )
                    except subprocess.CalledProcessError:
                        print(f"❌ Cannot create auth file for '{auth_config}'")
                        exit(5)

    if "disable_https" in domain and domain.disable_https:
        print(f"⚠️ HTTPS is disabled for domain '{domain_name}'")
        # Hash management of domain configs
        new_hash = compute_domain_hash(domain_name, domain)
        old_hash = get_domain_hash(DOMAIN_HASHES, domain_name)
        if new_hash == old_hash and path.isfile(path.join(LIVE, domain_name, "fullchain.pem")):
            # in this case we do not need to renew the certificate
            continue
        # let's create a new certificate
        store_domain_hash(DOMAIN_HASHES, domain_name, domain)
        # Generate self-signed certificates if needed
    else:
        if "cert" in domain and domain.cert == "self-signed":
            print(f"✅ using self-signed certificate for domain '{domain_name}'")
            live = f"{LIVE}/{domain_name}"
            makedirs(live, exist_ok=True)
            csr_config = path.join(live, "csr.conf")
            with open(csr_config, "w") as csr:
                template = env.get_template("csr.conf.j2")
                csr.write(template.render(domain_name=domain_name, domain=domain))
            try:
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
            except subprocess.CalledProcessError:
                print(f"❌ Cannot create self-signed certificate for domain '{domain_name}'")
                print("Certificate Signing Request Config:")
                with open(path.join(live, "csr.conf"), encoding="utf-8") as f:
                    content = f.read()
                print(content)
                exit(7)
        elif "cert" in domain and domain.cert == "own":
            print("✅ using own certificate for domain '{domain_name}'")


# Create final nginx config and replace entrypoint with nginx
with open(NGINX_DOT_CONF, "w") as config:
    template = env.get_template("nginx.conf.j2")
    config.write(template.render(modules=cfg.get("modules", {})))
with open(SMNRP_NGINX_CONFIG, "w") as config:
    template = env.get_template("smnrp.conf.j2")
    config.write(template.render(certrequest=False, domains=cfg.domains))

check_nginx_syntax()

pid = fork()
if pid == 0:
    # initiating cert renew process as a separate process
    cert_renew()
else:
    # this becomes the new PID 0
    args = argv[1:]
    if args:
        print(f"🙌 Executing {' '.join(args)}...")
        execvp(args[0], args)
    # else in the default case run nginx as the main process
    print("🙌 Starting nginx...")
    execvp(
        "nginx",
        ["nginx", "-g", "daemon off;"],
    )
