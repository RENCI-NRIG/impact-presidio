# impact-presidio
Webapp file server that uses SAFE to guard its contents

Quick notes for startup:
- Check out repo
- Do "docker-compose build"
- The directory "config" has all of the current CILogon CA certificates, in "ca-certs.pem"
- These were obtained from: https://cilogon.org/cilogon-ca-certificates.tar.gz
- This certificate bundle was un-tarred and concatenated thus:
cd cilogon-ca/certificates/
cat cilogon-*.pem > ../../ca-certs.pem
- Obtain a server certificate and key file for the server; we are using certbot.
- Make a directory "ssl"; copy the certificate into it as "SSL.crt" and the key into it as "SSL.key"
- Create a "projects" directory and populate it. It can be labeled using ".safelabels" files or xattrs.
- Replace the string "PRESIDIO_HOST" in "nginx/default.conf.template" with your desired hostname, and copy it to "nginx/default.conf"
- Finally, start the Docker containers as below:

docker-compose up -d presidio

docker-compose up -d nginx

