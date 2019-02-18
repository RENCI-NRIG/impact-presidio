#
# Presidio (a SAFE-mediated HTTP fileserver) Dockerfile
#

# Pull base image.
FROM python:3

# Define the deployment directory
ENV DEPLOYMENT /opt/presidio-deploy
ENV RUN_USER nobody
ENV RUN_GROUP nogroup

# Create the directory structure.
# "config" and "projects" are mountpoints intended for Docker bind mounts
RUN mkdir -p ${DEPLOYMENT} && \
        mkdir ${DEPLOYMENT}/config && \
        mkdir ${DEPLOYMENT}/projects && \
        mkdir ${DEPLOYMENT}/log && \
        chown -R ${RUN_USER}:${RUN_GROUP} ${DEPLOYMENT}/log

# Populate the directory structure.
COPY setup.py ${DEPLOYMENT}
COPY impact-presidio ${DEPLOYMENT}/impact-presidio

# Set up presidio and install all dependencies.
RUN cd ${DEPLOYMENT} && \
        pip install -e .

# Define ports
EXPOSE 8000

# Change user, and run.
USER ${RUN_USER}
WORKDIR ${DEPLOYMENT}
ENTRYPOINT gunicorn --bind=0.0.0.0:8000 --error-logfile=log/error_log --access-logfile=log/access_log --capture-output --certfile=config/cert.pem --keyfile=config/key.pem --ca-certs=config/ca-certs.pem --do-handshake-on-connect --cert-reqs 2 impact-presidio:app
