FROM nginx:1.31.1

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  PYTHONUNBUFFERED=1

# All following commands are done as root
USER root

# Define a volume for /etc/letsencrypt
# to make sure the requested certificates
# are persistent
VOLUME /etc/letsencrypt

# Install OS requirements and clean apt metadata in the same layer.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    apache2-utils \
    certbot \
    inotify-tools \
    libcap2-bin \
    python3 \
    python3-certbot-nginx \
    python3-pip \
  && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /tmp/* /var/tmp/*

# Create runtime directories
RUN mkdir -p \
  /etc/letsencrypt \
  /usr/share/nginx/html/error \
  /var/lib/letsencrypt \
  /var/log/nginx \
  /var/www/certbot \
  /web_root

# Copy an initial index html to the webroot
# normaly you would mount a directory
# to the webroot what will shadow this default
COPY ./nginx/index.html /usr/share/nginx/index.html
COPY ./nginx/background.jpg /usr/share/nginx/background.jpg
COPY ./nginx/favicon.ico /usr/share/nginx/favicon.ico
COPY ./nginx/dhparams.pem /usr/share/nginx/dhparams.pem

# Copy the errorpages
COPY ./nginx/errorpages/* /usr/share/nginx/html/error/.

# Install python dependencies
COPY ./pyproject.toml /tmp/smnrpx/pyproject.toml
RUN pip install --break-system-packages --prefer-binary --root-user-action ignore /tmp/smnrpx \
  && rm -rf /tmp/smnrpx /root/.cache/pip

# Create an smnrp user and group
RUN groupadd --gid 1000 smnrp \
  && useradd --uid 1000 --gid 1000 -m smnrp

# Copy the entrypoint
COPY ./entrypoint.py /entrypoint.py
COPY ./smnrpx /smnrpx
COPY ./smnrp_reset /smnrp_reset
COPY ./templates /templates
COPY ./smnrp_schema.yml /smnrp_schema.yml
RUN echo "" > /etc/nginx/nginx.conf
RUN chmod 755 /entrypoint.py /smnrp_reset

# let the smnrp user own the needed files and dirs
RUN chown -R smnrp:smnrp \
  /entrypoint.py \
  /smnrpx \
  /smnrp_reset \
  /etc/nginx/conf.d \
  /etc/nginx/nginx.conf \
  /var/cache/nginx \
  /var/lib/letsencrypt \
  /var/www \
  /etc/letsencrypt \
  /web_root \
  /var/log \
  /run

# Execute as user smnrp
USER smnrp

# Start the entrypoint
ENTRYPOINT [ "/entrypoint.py" ]
