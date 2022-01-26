#
# Presidio (a SAFE-mediated HTTP fileserver) Dockerfile
#

# Pull base image.
FROM pypy:3

# Define the deployment directories
ENV CONFIG /etc/impact_presidio
ENV DEPLOYMENT /opt/presidio-deploy
ENV PROJECTS /srv/projects
ENV LOGDIR /var/log/impact_presidio

# Define user and group to use
ENV GUNICORN_USER nobody
ENV GUNICORN_GROUP nogroup

# Add a convenience item
RUN apt-get update && apt-get -y install less

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

# Install rust to support latest versions of cryptography dependency.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y

# Set up presidio dependencies.
RUN export PATH="/root/.cargo/bin:${PATH}" && \
    cd ${DEPLOYMENT} && \
    pypy3 setup.py egg_info && \
    pip install -r *.egg-info/requires.txt

# Set up presidio itself
RUN export PATH="/root/.cargo/bin:${PATH}" && \
    cd ${DEPLOYMENT} && \
    pip install -e .

# Define ports
EXPOSE 8000

# Define number of workers
ENV NUM_WORKERS 2

# Define allowed IPs, with a default.
ENV ALLOWED_IPS localhost

# Define time zone, for logs
ENV TZ America/New_York

# Copy in profiler
COPY wsgi_profiler.py ${DEPLOYMENT}

# If you want to do profiling, do:
# export GUNICORN_ADDITIONAL_ARGS="-c ./wsgi_profiler.py"
env GUNICORN_ADDITIONAL_ARGS ""

# Change user, and run.
USER ${GUNICORN_USER}
WORKDIR ${DEPLOYMENT}
ENTRYPOINT gunicorn --bind=0.0.0.0:8000 --worker-class=gevent --workers="${NUM_WORKERS}" --keep-alive=0 --forwarded-allow-ips="${ALLOWED_IPS}" --error-logfile=${LOGDIR}/error_log --access-logfile=${LOGDIR}/access_log --capture-output --reuse-port ${GUNICORN_ADDITIONAL_ARGS} impact_presidio:app
