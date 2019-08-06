#!/bin/bash
TEST_URL="https://localhost/"
KEY=key.pem
CERT=cert.pem
CAFILE=ca-certs.pem

curl -v -G -L -c cookie_file --data "ImPACT-JWT=${IMPACT_JWT}" --key "${KEY}" --cert "${CERT}" --cacert "${CAFILE}" "${TEST_URL}"
