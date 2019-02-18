# impact-presidio
Webapp file server that uses SAFE to guard its contents

Quick notes for startup:
- Check out repo
- Do "docker build ."
- Tag the docker build; I'll use the tag "presidio_test" in the example below.
- Grab CA certificates from:
https://cilogon.org/cilogon-ca-certificates.tar.gz
- Un-tar certificate bundle, and concatenate pem files into a single cert bundle; something similar to:
cd cilogon-ca/certificates/
cat cilogon-*.pem > ../../ca-certs.pem
- Create a server certificate and key file for the server
- Place the server certificate, key, and CA certs file in a directory named "config"
- Create a "projects" directory and populate it.
- Finally, run your docker container similar to below; you will need to bind mount your config and projects directories:

docker run -dit --rm -p 8000:8000/tcp -v /srv/config:/opt/presidio-deploy/config -v /srv/projects:/opt/presidio-deploy/projects presidio_test

Presidio can also be build in a virtualenv (rather than in Docker).
The process is similar to the above:

- Check out the repo
- Create a virtualenv within the checkout directory; for example:
virtualenv --python=python3 presidio
- Activate the virtualenv:
source presidio/bin/activate
- After activating the virtualenv, install presidio from the repo directory by running pip:
pip install -e .
- Obtain server certificate, key, and CA bundle as described above
- Create and populate (or symlink to) a directory named "projects" in the repo directory
- Finally, run presidio; for an example of how you might do so, check out testing_scripts/test_run_presidio.sh

