import contextlib
import subprocess
from os import path, remove, symlink
from shutil import rmtree
from time import sleep

from smnrpx.constants import CERT_RENEW_TIMEOUT, DOMAIN_HASHES, LIVE
from smnrpx.hashing import compute_certificate_request_hash, get_domain_hash, store_hash_value


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


def create_dhparams(create: bool = True):
    dhparams_file = path.join(path.sep, "etc", "letsencrypt", "dhparams.pem")
    if path.isfile(dhparams_file):
        return

    if create:
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
            raise SystemExit(6)
        return

    src_dhparams_file = path.join(path.sep, "usr", "share", "nginx", "dhparams.pem")
    if not path.isfile(src_dhparams_file):
        return

    if path.islink(dhparams_file):
        remove(dhparams_file)
    elif path.isdir(dhparams_file):
        rmtree(dhparams_file)

    with contextlib.suppress(FileExistsError):
        symlink(src_dhparams_file, dhparams_file)


def handle_cert_request(grouped_domains: dict):
    for group_name, domain_specs in grouped_domains.items():
        vhost = None
        additional_domains: list[str] = []
        for domain_spec in domain_specs:
            if domain_spec["type"] == "vhost":
                if vhost is None:
                    vhost = domain_spec["domain"]
                else:
                    additional_domains.append(domain_spec["domain"])
                continue

            additional_domains.append(domain_spec["domain"])

        if vhost is None:
            continue

        cert_request_hash = compute_certificate_request_hash(vhost, additional_domains)
        current_hash = get_domain_hash(DOMAIN_HASHES, group_name)
        cert_path = path.join(LIVE, vhost, "fullchain.pem")
        if current_hash == cert_request_hash and path.isfile(cert_path):
            print(f"ℹ️ no need to request certificate for domain group '{group_name}'")
            continue

        print(f"✅ will request certificate for domain group '{group_name}'")
        try:
            domain_list = ",".join([vhost, *additional_domains])
            cmd = [
                "certbot",
                "certonly",
                "--webroot",
                "-w",
                "/var/www/certbot",
                "--register-unsafely-without-email",
                "-d",
                domain_list,
                "--rsa-key-size",
                "4096",
                "--agree-tos",
                "--force-renewal",
                "--log",
                "/tmp",
            ]
            subprocess.run(cmd, check=True)
            store_hash_value(DOMAIN_HASHES, group_name, cert_request_hash)

            target = path.join(LIVE, vhost)
            for domain_spec in domain_specs:
                if domain_spec["type"] == "vhost" and domain_spec["domain"] != vhost:
                    if path.isdir(target):
                        link = path.join(LIVE, domain_spec["domain"])
                        if path.islink(link):
                            remove(link)
                        elif path.isdir(link):
                            rmtree(link)
                        with contextlib.suppress(FileExistsError):
                            symlink(target, link)
        except subprocess.CalledProcessError as err:
            print(f"❌ Cannot request certificate for domain '{vhost}'")
            print(err)
            if path.isdir(path.join(LIVE, vhost)):
                rmtree(path.join(LIVE, vhost))
            raise SystemExit(3) from err
