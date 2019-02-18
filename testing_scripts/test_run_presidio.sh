#!/bin/bash
KEY=key.pem
CERT=cert.pem
CAFILE=ca-certs.pem

gunicorn --certfile="${CERT} --keyfile="${KEY}" --ca-certs="${CAFILE}" --do-handshake-on-connect --cert-reqs 2 impact-presidio:app
