import contextlib
import subprocess
from os import path, remove, symlink
from shutil import rmtree
from time import sleep

from smnrpx.constants import CERT_RENEW_TIMEOUT, LIVE


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
    for _, domain_specs in grouped_domains.items():
        vhost = None
        sans: list[str] = []
        for domain_spec in domain_specs:
            if domain_spec["type"] == "vhost":
                vhost = domain_spec["domain"]
                sans = [
                    item["domain"]
                    for item in domain_specs
                    if item["domain"] != vhost
                ]
                break

        if vhost is None:
            continue

        print(f"✅ requesting certificate from letsencrypt for domain '{vhost}'")
        try:
            domain_list = ",".join([vhost, *sans])
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
