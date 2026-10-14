# Secure Multifunctional Nginx Reverse Proxy _eXtended version_

SMNRP*X* is a reverse proxy based on nginx, configured with one YAML file. The full documentation, with every
configuration option, is in the [README on GitHub](https://github.com/ETH-NEXUS/smnrpx#readme).

## Features

- HTTPS certificates from Let's Encrypt (requested and renewed automatically), self-signed, or your own
- Reverse proxy and load balancing to upstream containers, file serving (`alias`) and redirects
- High baseline security: TLS 1.3 by default, security headers, an optional `Content-Security-Policy`, OCSP stapling
- `421` for https requests whose `Host` differs from the TLS server name
- Basic authentication, IP allow lists and `auth_request` / oauth2-proxy checks per location
- Maintenance mode

## Quick start

`smnrp.yml`:

```yaml
domains:
  dom.org:
    sans:
      - www.dom.org
    upstreams:
      api:
        - api:5000
    locations:
      - proxy:
          uri: /api/
          proto: http
          upstream: api
          path: /api/
```

`docker-compose.yml`:

```yaml
configs:
  smnrp:
    file: ./smnrp.yml
volumes:
  smnrp_data:
services:
  ws:
    image: ethnexus/smnrpx
    ports:
      - 80:80
      - 443:443
    configs:
      - source: smnrp
        target: /run/configs/smnrp.yml
    volumes:
      # Keep the certificates, or Let's Encrypt may block new requests for a day.
      - smnrp_data:/etc/letsencrypt
    restart: unless-stopped
```

## Tags

- `latest`, `<major>`, `<major>.<minor>`, `<version>`: releases
- `-net-bind` variants (for example `3-net-bind`): for chaining instances with `network_mode: host`
- `main`: the current `main` branch, not for production

Migrating from `ethnexus/smnrp`? The [migration guide](https://github.com/ETH-NEXUS/smnrpx#migration) shows how the
environment variables map to the YAML file.
