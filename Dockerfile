# syntax=docker/dockerfile:1.6.0
# this Dockerfile is located at the root so the build context
# includes oauth2_provider which is a requirement of the
# tests/app/idp. This way we build images with the source
# code from the repos for validation before publishing packages.

FROM python:3.11.6-slim as builder

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ENV DEBUG=False
ENV ALLOWED_HOSTS="*"
ENV TEMPLATES_DIRS="/data/templates"
ENV STATIC_ROOT="/data/static"
ENV DATABASE_URL="sqlite:////data/db.sqlite3"

RUN apt-get update
# Build Deps
RUN apt-get install -y --no-install-recommends gcc libc-dev python3-dev git openssh-client libpq-dev file libev-dev
# bundle code in a virtual env to make copying to the final image without all the upstream stuff easier.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
# need to update pip and setuptools for pep517 support required by gevent.
RUN pip install --upgrade pip
RUN pip install --upgrade setuptools
COPY . /code
WORKDIR /code/tests/app/idp
RUN pip install -r requirements.txt
RUN pip install gunicorn
RUN python manage.py collectstatic --noinput



FROM python:3.11.6-slim

# allow embed sha1 at build time as release.
ARG GIT_SHA1

LABEL org.opencontainers.image.authors="https://github.com/django-oauth/django-oauth-toolkit/blob/master/AUTHORS"
LABEL org.opencontainers.image.source="https://github.com/django-oauth/django-oauth-toolkit"
LABEL org.opencontainers.image.revision=${GIT_SHA1}


ENV SENTRY_RELEASE=${GIT_SHA1}

# disable debug mode, but allow all hosts by default when running in docker
ENV DEBUG=False
ENV ALLOWED_HOSTS="*"
ENV TEMPLATES_DIRS="/data/templates"
ENV STATIC_ROOT="/data/static"
ENV DATABASE_URL="sqlite:////data/db.sqlite3"




COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY --from=builder /code /code
RUN mkdir -p /data/static /data/templates
COPY --from=builder /code/tests/app/idp/static /data/static
COPY --from=builder /code/tests/app/idp/templates /data/templates

WORKDIR /code/tests/app/idp
RUN apt-get update && apt-get install -y \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*
EXPOSE 80
VOLUME ["/data" ]
CMD ["gunicorn",  "idp.wsgi:application",  "-w 4 -b 0.0.0.0:80 --chdir=/code --worker-tmp-dir /dev/shm --timeout 120  --error-logfile '-' --log-level debug --access-logfile '-'"]
