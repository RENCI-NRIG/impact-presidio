#!/bin/bash
TEST_URL="https://localhost:8000/"
KEY=key.pem
CERT=cert.pem
CAFILE=ca-certs.pem

curl -v --key "${KEY}" --cert "${CERT}" --cacert "${CAFILE}" "${TEST_URL}"
