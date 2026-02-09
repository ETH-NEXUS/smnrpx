FROM nginx:1.29.3

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 
ENV PIP_NO_CACHE_DIR=1
ENV PYTHONUNBUFFERED=1

# All following commands are done as root
USER root

# Define a volume for /etc/letsencrypt
# to make sure the requested certificates
# are persistent
VOLUME /etc/letsencrypt

# Define a volume for /var/log
# to make sure the analytics data
# is persistent
VOLUME /var/log

# Install the requirements
RUN apt-get update && apt-get install -y \
  python3 \
  python3-pip \
  certbot \
  python3-certbot-nginx \
  inotify-tools \
  apache2-utils

# Install debugging tools
RUN apt-get install -y \
  vim \
  procps
  
# Clean up the apt cache
RUN apt-get clean autoclean && apt-get autoremove -y && rm -rf /var/lib/{apt,dpkg,cache,log}/

# Cerate the web root directory
RUN mkdir -p /web_root

# Copy an initial index html to the webroot
# normaly you would mount a directory
# to the webroot what will shadow this default
COPY ./nginx/index.html /usr/share/nginx/index.html
COPY ./nginx/background.jpg /usr/share/nginx/background.jpg
COPY ./nginx/favicon.ico /usr/share/nginx/favicon.ico

# Create the webroot for certbot
RUN mkdir -p /var/www/certbot

# Add the dh-params to the image
RUN mkdir -p /etc/letsencrypt
COPY ./ssl-dhparams.pem /usr/share/nginx/ssl-dhparams.pem

# Copy the nginx configurtion files
COPY ./nginx/nginx.conf /etc/nginx/nginx.conf
# COPY ./nginx/conf.d /etc/nginx/conf.d

# Copy the errorpages
RUN mkdir -p /usr/share/nginx/html/error
COPY ./nginx/errorpages/* /usr/share/nginx/html/error/.

# Add additional required folders
RUN mkdir -p /var/lib/letsencrypt
RUN mkdir -p /var/log/nginx

# Install python dependencies
COPY ./pyproject.toml /tmp/pyproject.toml
RUN pip install --break-system-packages --prefer-binary --root-user-action ignore /tmp

# Create an smnrp user and group
RUN groupadd --gid 1000 smnrp \
  && useradd --uid 1000 --gid 1000 -m smnrp

# Copy the entrypoint
COPY ./entrypoint.py /entrypoint.py
COPY ./analyser.sh /analyser.sh
COPY ./reloader.sh /reloader.sh
COPY ./renewer.sh /renewer.sh
COPY ./smnrp_reset /smnrp_reset
COPY ./templates /templates
COPY ./smnrp_schema.yml /smnrp_schema.yml
RUN chmod 755 /entrypoint.py /analyser.sh /reloader.sh /renewer.sh /smnrp_reset

# let the smnrp user own the needed files and dirs
RUN chown -R smnrp:smnrp \
  /entrypoint.py \
  /analyser.sh \
  /reloader.sh \
  /renewer.sh \
  /smnrp_reset \
  /etc/nginx/conf.d \
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