from box import Box

from smnrpx.constants import DOMAIN_REGEX


def get_www_redirect_domain(domain_name: str, domain) -> str | None:
    if not domain.get("redirect_www", False):
        return None
    if domain_name.startswith("www."):
        return None
    return f"www.{domain_name}"


def get_redirect_hosts(domain_name: str, domain) -> list[str]:
    # Host names that are served by this vhost but answered with a redirect to it,
    # generated from 'redirect_www' and listed in 'redirect_from'.
    redirect_hosts = []
    www_redirect_domain = get_www_redirect_domain(domain_name, domain)
    if www_redirect_domain:
        redirect_hosts.append(www_redirect_domain)

    for redirect_host in domain.get("redirect_from", []) or []:
        if not redirect_host or redirect_host == domain_name:
            continue
        if redirect_host not in redirect_hosts:
            redirect_hosts.append(redirect_host)

    return redirect_hosts


def get_effective_sans(domain_name: str, domain) -> list[str]:
    sans = list(domain.get("sans", []) or [])
    for redirect_host in get_redirect_hosts(domain_name, domain):
        if redirect_host not in sans:
            sans.append(redirect_host)
    return sans


def get_grouped_domains(cfg: Box):
    # Collect all LetsEncrypt vhosts and SANs, grouped by main domain.
    cert_domain_specs = []
    grouped_domains = {}
    for domain_name, domain in cfg.domains.items():
        if domain.get("disable_https", False):
            continue
        if "cert" not in domain or domain.cert == "letsencrypt":
            cert_domain_specs.append({"domain": domain_name, "type": "vhost"})
            for san in get_effective_sans(domain_name, domain):
                cert_domain_specs.append({"domain": san, "type": "san"})

    main = None
    for domain_spec in cert_domain_specs:
        match = DOMAIN_REGEX.match(domain_spec["domain"])
        if not match:
            print(f"⚠️ '{domain_spec['domain']}' is not a correct domain name, ignoring")
            continue

        if domain_spec["type"] == "vhost":
            main = match.group("main")

        if main is None:
            continue

        if main not in grouped_domains:
            grouped_domains[main] = []

        grouped_domains[main].append(domain_spec)

    return grouped_domains
