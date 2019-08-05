#
# Presidio (a SAFE-mediated HTTP fileserver) Dockerfile
#

# Pull base image.
FROM python:3-alpine

# Define the deployment directory
ENV CONFIG /etc/impact_presidio
ENV DEPLOYMENT /opt/presidio-deploy
ENV PROJECTS /srv/projects
ENV LOGDIR /var/log/impact_presidio

# Add dependencies
RUN apk add --update --no-cache build-base make libffi-dev openssl-dev

# Create the directory structure.
# "config" and "projects" are mountpoints intended for Docker bind mounts
RUN mkdir -p ${CONFIG} && \
        mkdir -p ${DEPLOYMENT} && \
        mkdir -p ${PROJECTS} && \
        mkdir -p ${LOGDIR}

# Populate the directory structure.
COPY setup.py ${DEPLOYMENT}
COPY impact_presidio ${DEPLOYMENT}/impact_presidio

# Set up presidio and install all dependencies.
RUN cd ${DEPLOYMENT} && \
        pip install -e .

# Define ports
EXPOSE 8000

# Define number of workers
ENV NUM_WORKERS 1

# Define allowed IPs, with a default.
ENV ALLOWED_IPS localhost

# Change user, and run.
WORKDIR ${DEPLOYMENT}
ENTRYPOINT gunicorn --bind=0.0.0.0:8000 --workers="${NUM_WORKERS}" --forwarded-allow-ips="${ALLOWED_IPS}" --error-logfile=${LOGDIR}/error_log --access-logfile=${LOGDIR}/access_log --capture-output impact_presidio:app
