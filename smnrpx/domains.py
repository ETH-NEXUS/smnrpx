from box import Box

from smnrpx.constants import DOMAIN_REGEX


def get_grouped_domains(cfg: Box):
    # Collect all LetsEncrypt vhosts and SANs, grouped by main domain.
    cert_domain_specs = []
    grouped_domains = {}
    for domain_name, domain in cfg.domains.items():
        if "cert" not in domain or domain.cert == "letsencrypt":
            cert_domain_specs.append({"domain": domain_name, "type": "vhost"})
            if "sans" in domain:
                for san in domain.sans:
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
