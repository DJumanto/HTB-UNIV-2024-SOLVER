FROM node:alpine

ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
# Install necessary packages including Chromium and its dependencies
RUN apk add --no-cache \
    supervisor \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont \
    apache2-utils

RUN mkdir -p /email 
COPY email-app /email

WORKDIR /email
RUN npm i

RUN export RANDOM_VALUE=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) \
    && htpasswd -nbBC 10 test "$RANDOM_VALUE" > /mailhog-auth && echo $RANDOM_VALUE > /email/password.txt

# Setup Mailhog
WORKDIR /
RUN wget https://github.com/mailhog/MailHog/releases/download/v1.0.1/MailHog_linux_amd64
RUN chmod +x MailHog_linux_amd64

# Setup app
RUN mkdir -p /app

# Add application
WORKDIR /app
COPY challenge .

# Copy flag
COPY flag.txt /

# Install dependencies (including Puppeteer)
RUN yarn

# Puppeteer will use the chromium from the OS instead of downloading its own
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

# Setup supervisord
COPY config/supervisord.conf /etc/supervisord.conf

# Expose the port node-js is reachable on
EXPOSE 1337
EXPOSE 8080

# Start supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
