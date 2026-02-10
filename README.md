# Secure Multifunctional Nginx Reverse Proxy _eXtended version_

The _Secure Multifuctional Nginx Reverse Proxy eXtended version (SMNRP)_ is a reverse proxy based on nginx.

![SMNRP](https://raw.githubusercontent.com/ETH-NEXUS/smnrp/main/img/SMNRP.png)

## Migration

To migrate from smnrp to smnrpx you basically need to convert the environment variables to a yaml file. The mapping should be straight forward.
The functionality stays the same except:

- bypass is no longer supported as a certificate provider
- analytics is no longer supported

## Features

### HTTPS Certificates

- Automatic generation and renewal of https certificates (using [Let's Encrypt](https://letsencrypt.org/)
- Automatic generation of a self signed certificate
- Usage of custom (own) certificates

### Usage options

- Reverse proxy to a web application
- Load balancer to different locations

### Security features

- High baseline security
- Customizable `Content-Security-Policy`
- OCSP stapling [ℹ️](https://www.ssls.com/knowledgebase/what-is-ocsp-stapling/)
- Basic authentication to specific locations

### Additional features

- [Maintenance mode](#maintenance-mode)

## Getting started

SMNRP*X* can be configured **using a yaml configuration file**. All possible configuration options are described in this readme.

To integrate the SMNRP*X* into your web application you just need to configure the yaml file (e.g. smnrp.yml).
Alternatively you can assign the yml configuration to the environment variable `SMNRP`.

```env_file
SMNRP="
<yaml file content>
"
```

Let's start with a full examples.

```yaml
domains:
  # The name of the domain (used as *cn* in the certificate)
  dom.org:
    # If not defined, the certificate will be requested from Let's Encrypt
    # cert: self-signed
    # Subject alternative names (SAN) (other names for the **same** domain)
    sans:
      - www.dom.org
    # Upstreams
    upstreams:
      # Name of the upstream (freely eligible)
      api:
        # List of host:port combinations to define the upstream servers
        - echo:80
    # Ports to listen on (one for http and one for https traffic)
    ports:
      http: 80
      https: 8443
    # The Content Security Policy for this domain
    csp: default-src 'self' http: https: data: blob: 'unsafe-inline'
    # Hardening parameters (please read the details below)
    server_tokens: off
    proxy_buffer_size: 32k
    client_max_body_size: 1m
    client_body_buffer_size: 1k
    allow_tls1.2: true
    disable_ocsp_stapling: true

  search.7f000001.nip.io:
    # The certificate is created as a self-signed one by SMNRPX,
    # if set to 'own' you need to map you own certificates to the right path
    cert: self-signed
    sans:
      - www.search.7f000001.nip.io
    upstreams:
      google:
        - google.com:443
    # Locations defined by type (proxy, alias, redirect)
    locations:
        # A proxy location defines what uri is proxied to what target (basically an upstream)
      - proxy:
          # Set headers to disable browser cache (helpful while developing web apps)
          disable_cache: true
          # What uri to proxy,
          uri: /search
          # over which protocol,
          proto: https
          # to what upstream,
          upstream: google
          # and what path
          path: /
          # The location should be password protected (by basic authentication),
          auth:
              # with this user,
            - user: admin
              # and this password
              password: secret
          # Only allow access to this location from the listed networks
          whitelist:
            - 127.0.0.1/32
          # Add custom configuration lines to this location (e.g. additional proxy headers)
          custom:
            - proxy_set_header Host $http_host
        # The alias location maps a uri to a local filesystem path
      - alias:
          # The uri to map,
          uri: /media
          # to what local filesystem path
          path: /usr/local/media
          # Add internal clause to the location
          internal: true
          # Add try_files clause to the location
          try_files: true
          # The location should be password protected (by basic authentication),
          auth:
              # with this user,
            - user: user
              # and this password
              password: user
        # The redirect location redirects all traffic to a different url with a 301 HTTP status code
      - redirect:
          # The uri to redirect,
          uri: /redir
          # to this new location, trowing a 301 HTTP status code
          url: http://google.com
```

We follow with some additional minimal examples.

## Examples

### Simple reverse proxy

To start with the most basic configuration to use SMNRP*X* as a reverse proxy to a web application while requesting the certificates automatically
from Let's Encrypt.

![Example1](https://raw.githubusercontent.com/ETH-NEXUS/smnrp/main/img/SMNRP_ex1.png)

```yaml
domains:
  dom.org:
    sans:
      - www.dom.org
  upstreams:
    api:
      - api:5000
  locations:
    proxy:
      uri: /api/
      proto: http
      upstream: api
      path: /api/
    alias:
      uri: /api/static
      path: /usr/share/static
```

In this example the domain `dom.org` is configured.
The domain name is taken as the default domain name and ends up as the _common name (cn)_ in the certificate.
The domain names under `sans` are additional domain names for the same domain and end up as _Subject Alternative Names (SAN)_ in the certificate.

The upstream `api` points to the host `api` and port `5000`. This is often a container service name where the web applications REST API is running, but can be
any `hostname:port` combination reachable from smnrp.

There are different location types. In this case we use a `proxy` location to proxy the requests to the api service and an `alias` location to
configure an alias for local path. The `proxy` location defines what `uri` is proxied to what `proto`, what `upstream` and what `path`. The `alias` location
defines what `uri` is aliased by what local `path`.

This leads to the following behavior:

```
dom.org/api/       --       proxy         --> http://api:5000/api/
dom.org/api/static --aliased to local path--> /usr/local/static
```

### Simple load balancing

The following example shows the load balancing mode.

![Example2](https://raw.githubusercontent.com/ETH-NEXUS/smnrp/main/img/SMNRP_ex2.png)

```yaml
domains:
  dom.org:
    sans:
      - www.dom.org
    upstreams:
      loadbalancer:
        - srv1.dom.org:443
        - srv2.dom.org:443
    locations:
      proxy:
        uri: /
        proto: http
        upstream: loadbalancer
        path: /
```

In this scenario the certificates are requested from Let's Encrypt as in the first example. The traffic is then load balanced to
two servers `srv1.dom.org` and `srv2.dom.org`. The load balancing is internally configured as:

```nginx
upstream loadbalancer {
  server srv1.dom.org:443 max_fails=3 fail_timeout=10s;
  keepalive 32;
  server srv2.dom.org:443 max_fails=3 fail_timeout=10s;
  keepalive 32;
}
```

The requests are equally distributed to the two servers. If one fails, the others are used. This mechanism can only be used for high availability
scenarios **without** shared storage or shared state.

### Virtual host support

Each domain becomes a virtual host in SMNRP*X*. Just configure multiple `domains` with different names.

## Configuration

### `domains`

Each domain has a name (`domain_name`), the _common name (cn)_ and optionally `sans`, the _Subject Alternative Names_.
The default root folder for each domain is located at `/web_root/domain_name`.
A domain contains differents `upstreams`, `locations` and additional configuration parameters:

- `cert`: Can have the values 'self-signed' or 'own' or not defined to define how the certificate is generated. Default is through Let's Encrypt.
- `csp`: The Content security policy. Default is the nginx default.
- `proxy_buffer_size`: The proxy buffer size.
- `client_max_body_size`: The client max body size.
- `client_body_buffer_size`: The client body buffer size.
- `allow_tls1.2`: true or false, if you want to support also tls1.2. Default only supports tls1.3
- `disable_ocsp_stapling`: true or false, if you want to disable ocsp stapling. Default is false.

### `upstreams`

Upstreams list all `upstreams` that can be referenced in the `locations` configuration as a list of `hosts:port` combinations.

### `locations`

Locations are the core part of the configuration. Here you configure different types of locations to define what `uri` is handled how:

#### `proxy` location

The `proxy` location forwards the traffic arriving at the defined `uri` to `proto`://`upstream`/`path`. You can configure additional configuration parameters:

- `disable_cache`: true or false, to add headers to this location to disable the browser cache. Default is false.
- `auth`: To enable basic_authentication for this location. If configured you must add a list of `user`, `password` combinations.
- `whitelist`: To only allow a configured list of network segments to access this location.
- `custom`: To add custom configuration entries such as additional or different proxy headers.

```yaml
locations:
  - proxy:
      disable_cache: true
      uri: /api/
      proto: http
      upstream: api
      path: /api/
      auth:
        - user: admin
          password: admin
        - user: user
          password: secret
      whitelist:
        - 127.0.0.1
      custom:
        - proxy_set_header Host $http_host
```

#### `alias` location

The `alias` location is to serve files from a defined local path. For example if you have static files in the local path `/usr/local/static` that
you want to serve if the uri `/api/static` is requested. There are additional configuration settings you can add:

- `internal`: true or false, adds the `internal` clause to an alias location. This can be used to protect the file in this location from public access. Such files are only accessible by setting the `X-Accel-Redirect` header
- `try_files`: adds a `try_files` clause to the `alias` location.
- `auth`: same as in the `proxy` location

```yaml
locations:
  - alias:
      uri: /api/static
      path: /usr/local/static
      internal: true
      try_files: true
      auth:
        - user: user
          password: user
```

#### `redirect` location

The redirect location is used to redirect a location to another one returning a 301 HTTP status code (_permanent redirect_). For example if you want to
redirect the uri `/redir` to the url `https://google.com`. There are no additional configuration parameters available.

```yaml
locations:
  - redirect:
      uri: /redir
      url: https://google.com
```

#### Example

```yaml
upstreams:
  postman:
    - postman-echo.com:443
locations:
  - alias:
      uri: /
      path: /web_root/dom.org/
      try_files: true
      auth:
        user: admin
        password: admin
  - proxy:
      uri: /api/
      proto: https
      upstream: postman
      path: /get/
  - redirect:
      uri: /redirect/
      url: /other-location/
```

This example

- _aliases_ (nginx: `alias`) the `/` path to `/web_root/dom.org/`,
- adds a `try_files` clause as well as a `auth_basic` clause to
  the location section.
- The `/api/` path is _proxied_ (nginx: `proxy_pass`) to `https://postman-echo.com/get/`.

#### Translation to nginx config

Basically the translation inside the nginx config is

- for an `alias`:

```nginx
location <path> {
  alias <alias>;
  try_files $uri $uri/ /index.html;      <--[Only if try_files is true]
}
```

- for a `proxy_url`:

```nginx
location <path> {
  proxy_pass <proxy_url>;
}
```

- for `auth_basic`, only if flag `auth` is configured:

```nginx
location <path> {
  auth_basic "Authorization Required";
  auth_basic_user_file <path_to_user_pw_list>;   <--[Derived from user/password configurations]
}
```

- for whitelisting, only if `whitelist` is configured:

```nginx
location <path> {
  allow <network-1>      <--[Networks are derived from 'whitelist']
  allow <network-2>
  deny all;              <--[All other IPs are denied]
}
```

- for _permanent redirect_, only if location type is `redirect`:

```nginx
location <path> {
  return 301 <alias|proxy_url>;
}
```

If you want to redirect to another container you need to use the _service name_ of the particular service as the host name.

If you only want to proxy to the configured `upstreams`, just don't configure `locations`.

- for `internal`, only if `internal` is `true`:

```nginx
location <path> {
  internal;
  alias <alias>;
}
```

### custom proxy location configurations

You can define additional nginx configuration lines for a `proxy` location.

```yaml
custom:
  - proxy_set_header Host $http_host
  - proxy_set_header X-Forwarded-Host $http_host
```

This example adds two custom config lines to the location block `location /api/`:

```nginx
location /api/ {
  ...
  proxy_set_header Host $http_host
  proxy_set_header X-Forwarded-Host $http_host
  ...
}
```

> Hint: Please be aware that the SMNRP default proxy config is included in the location BEFORE the custom configs.
> If `disable_default_headers` is set to `false` no default headers are added to the location block.

### cert

If set to `self-signed` SMNRP is generating self signed certificates instead of gathering it from Let's Encrypt.
If set to `own` SMNRP will not create any certificate but it requires the following two files to be mapped into the container (i.e. as docker read-only volume):

- `/etc/letsencrypt/live/${domain}/fullchain.pem`
- `/etc/letsencrypt/live/${domain}/privkey.pem`

Here is an example:

```yaml
  ...
  ws:
    image: ethnexus/smnrpx
    volumes:
      ...
      - /path/to/dom.org.fullchain.pem:/etc/letsencrypt/live/dom.org/fullchain.pem:ro
      - /path/to/dom.org.key.pem:/etc/letsencrypt/live/dom.org/privkey.pem:ro
```

### `SMNRP_CSP`

You can define the `Content-Security-Policy` header. If this is not defined, none is used. The following example shows the most secure one:

```yaml
csp: default-src 'self' http: https: data: blob: 'unsafe-inline'
```

### `SMNRP_DISABLE_HTTPS`

If set to `true`, SMNRP will completely ignore https for communication and only listen on port 80 to serve the resources.

## Configure the listening ports

To configure on which ports the nginx is listening on internally you can use the following environment variables:

```yaml
domain:
  ports:
    http: 80
    https: 443
```

With the `http` you can configure the **http server port** of nginx. Default is `80`.
With the `https` you can configure the **ssl server port** nginx is listening on. Default is `443`.

## Apply custom configurations

`SMNRP` also loads `*.nginx` files in the directory `/etc/nginx/conf.d/custom/*.nginx`. You can bind mount or copy a local directory
including your custom configs to `/etc/nginx/conf.d/custom/`.

```yaml
services:
  ws:
    image: ethnexus/smnrpx
    volumes: ...
      - ./custom/configs:/etc/nginx/conf.d/custom
```

## Integration into `docker-compose`

To integrate SMNRP*X* into docker compose to setup a reverse proxy to the application, you need to add the following part into you `docker-compose.yml`:

```yaml
volumes:
  web_root:
  smnrp_data:
  log_data:
configs:
  smnrp:
    - file: ./smnrp.yml
services:
  ws:
    image: ethnexus/smnrpx
    volumes:
      - web_root:/web_root/<domain_name>
      - smnrp_data:/etc/letsencrypt
    ports:
      - 80:80
      - 443:443
    configs:
      - source: smnrp
        target: /run/configs/smnrp.yml
    # Optional if you want to paste the configuration using the
    # 'SMNRP' environment variable
    # env_file: .env
    restart: unless-stopped
    depends_on:
      - ui
      - api
  ui:
    ...
    volumes:
      - "web_root:/path/to/webapp"
    ...
  api:
    ...
```

Your web application files need to be generated into the docker volume `web_root` that needs to be mapped to `/web_root/<domain_name>`.

Essential is the `smnrp_data` volume. It should **always** bind mounted to `/etc/letsencrypt`, otherwise SMNRP may create too many requests to Let's Encrypt and gets blocked for about 24h to request certificates.
If you are using a local directory to bind mount `/etc/letsencrypt` (i.e. `smnrp_data:/etc/letsencrypt`).

### Integration into `docker-compose` while chaining SMNRP*X* instances

In case you want to chain SMNRP`_X_ instances on the same host you need to configure the

- `network_mode` to `host` and
- omit the `ports` configuration.

```yaml
volumes:
  smnrp_data:
  log_data:
services:
  ws:
    image: ethnexus/smnrpx
    volumes:
      - smnrp_data:/etc/letsencrypt
    ...
    network_mode: host
```

## Maintenance mode

To enable the maintenance mode you need to touch the file `.maintenance` into the folder `/web_root/<domain_name>`.
As long as the file exists SMNRP*X* will return `503 Service unavailable` and displays a nice maintenance page.

### Change the maintenance page

To add a custom maintenance page you need to overwrite the file `/usr/share/nginx/html/error/maintenance.html`.

```yaml
---
volumes:
  - ./my-maintenance.html:/usr/share/nginx/html/error/maintenance.html
```

### Script to enable, disable the maintenance mode

Here is a script that you could use to enable, disable the maintenance mode with one command (`maint.sh`):

```bash
#!/usr/bin/env bash

DC_EXEC="docker-compose -f docker-compose.yml -f docker-compose.prod.yml exec ws"

if [[ "$1" == "on" ]]; then
    ${DC_EXEC} sh -c 'touch /web_root/.maintenance'
elif [[ "$1" == "off" ]]; then
    ${DC_EXEC} sh -c 'rm -f /web_root/.maintenance'
else
    echo "Please specify 'on' or 'off'"
    exit 1
fi
```

### Change the Authorization Required page

To add a custom _Authorization Required_ page you need to overwrite the file `/usr/share/nginx/html/error/auth_required.html`.

```yaml
---
volumes:
  - ./my-auth_required.html:/usr/share/nginx/html/error/auth_required.html
```

## Detect and handle certificate renewals on host

`SMNRP` is adding a file called like the domain for which the certificate update happened into the directory `/signal`. You can bind mount this directory and run a cronjob on your host os to detect changes. This can be essential, for example if you want to restart a mail server after the Let's Encrypt certificate has been renewed. An example script could look like this:

```bash
#!/usr/bin/env bash

SIGNAL_DIR="/path/to/signal"
DOMAIN="domain.of.interest"

if [ -f "${SIGNAL_DIR}/${DOMAIN}" ]; then
    echo "##############"
    echo `date`
    rm -f "${SIGNAL_DIR}/${DOMAIN}"
    ### EXAMPLE to reload postfix
    postfix reload
    service dovecot reload
    ### you can add your own logic here
fi
```

The following entry can be added to the repository's owners crontab:

```crontab
* * * * * (sudo /path/to/scripts/certRenew.sh 2>&1) >> /path/to/logs/certRenew.log
```

## Reset smnrp

If you went into troubles because of too many different configuration changes, you may want to reset smnrp:

```bash
docker exec <smnrp-container> /smnrp_reset
docker restart <smnrp-container>
```

This will basically remove already downloaded certificates and forces `SMNRP` to request a new certificate after the container restart.

## Configure hardening parameters

ℹ️ The default values are the most secure ones.

### `client_max_body_size`

Set the `client_max_body_size`, default is `1m`. This must be set to support large file uploads through SMNRP.

```bash
client_max_body_size: 1m
```

### `server_tokens`

Set the `server_tokens` parameter for this server, default is `off`.

```bash
server_tokens: off
```

### `client_body_buffer_size`

Set the `client_body_buffer_size` parameter for this server, default is `1k`. Nginx default would be `8k|16k`

```bash
client_body_buffer_size: 1k
```

### `large_client_header_buffers`

Set the `large_client_header_buffers` parameter for this server, default is `2 1k`. Nginx default would be `4 8k`

```bash
large_client_header_buffers: 2 1k
```

### `proxy_buffer_size`

Set the `proxy_buffer_size` parameter for this server, default is `32k`. Nginx default would be `8k`

```bash
proxy_buffer_size: 32k
```
