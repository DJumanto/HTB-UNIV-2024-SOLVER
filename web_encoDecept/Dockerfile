FROM ruby:3.4-rc-alpine3.20

RUN apk add --no-cache --update supervisor gcc musl-dev python3 py3-pip python3-dev chromium chromium-chromedriver nginx

RUN apk update && apk add --no-cache \
    build-base \
    linux-headers \
    libxml2-dev \
    libxslt-dev \
    libc-dev \
    yaml-dev \
    zlib-dev \
    make \
    gcc \
    g++ \
    bash \
    tzdata \
    libffi-dev \
    file \
    git \
    gcompat \
    zip

RUN python3 -m pip install --upgrade pip --break-system-packages

RUN pip install djangorestframework PyJWT selenium --break-system-packages

RUN mkdir -p /frontend /backend

COPY interstellarAPI /backend
COPY contract_frontend /frontend

COPY config/supervisord.conf /etc/supervisord.conf
COPY config/nginx.conf /etc/nginx/nginx.conf
RUN mkdir -p /var/cache/nginx/my_cache

WORKDIR /frontend
RUN bundle install
RUN rails db:migrate

WORKDIR /backend
RUN python3 manage.py makemigrations
RUN python3 manage.py migrate
RUN python3 manage.py reset_and_seed

EXPOSE 1337

ENV PYTHONDONTWRITEBYTECODE=1

COPY flag.txt /

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
