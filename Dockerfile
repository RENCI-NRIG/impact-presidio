#
# Presidio (a SAFE-mediated HTTP fileserver) Dockerfile
#

# Pull base image.
FROM python:3-alpine

# Define the deployment directories
ENV CONFIG /etc/impact_presidio
ENV DEPLOYMENT /opt/presidio-deploy
ENV PROJECTS /srv/projects
ENV LOGDIR /var/log/impact_presidio

# Define user and group to use
ENV GUNICORN_USER nobody
ENV GUNICORN_GROUP nogroup

# Add dependencies
RUN apk add --update --no-cache build-base make libffi-dev openssl-dev tzdata

# Create the directory structure.
# "config" and "projects" are mountpoints intended for Docker bind mounts
RUN mkdir -p ${CONFIG} && \
        mkdir -p ${DEPLOYMENT} && \
        mkdir -p ${PROJECTS} && \
        mkdir -p ${LOGDIR} && \
        chown -R ${GUNICORN_USER}:${GUNICORN_GROUP} ${LOGDIR}

# Populate the directory structure.
COPY setup.py ${DEPLOYMENT}
COPY impact_presidio ${DEPLOYMENT}/impact_presidio

# Set up presidio and install all dependencies.
RUN cd ${DEPLOYMENT} && \
        pip install -e .

# Define ports
EXPOSE 8000

# Define number of workers
ENV NUM_WORKERS 6

# Maximum number of requests per worker
ENV MAX_REQUESTS_PER_WORKER 50

# Define worker timeout
ENV WORKER_TIMEOUT 180

# Randomization factor, for max requests
ENV MAX_REQUESTS_JITTER 20

# Define allowed IPs, with a default.
ENV ALLOWED_IPS localhost

# Define time zone, for logs
ENV TZ America/New_York

# Change user, and run.
USER ${GUNICORN_USER}
WORKDIR ${DEPLOYMENT}
ENTRYPOINT gunicorn --bind=0.0.0.0:8000 --workers="${NUM_WORKERS}" --max-requests="${MAX_REQUESTS_PER_WORKER}" --max-requests-jitter="${MAX_REQUESTS_JITTER}" --timeout="${WORKER_TIMEOUT}" --forwarded-allow-ips="${ALLOWED_IPS}" --error-logfile=${LOGDIR}/error_log --access-logfile=${LOGDIR}/access_log --capture-output impact_presidio:app
