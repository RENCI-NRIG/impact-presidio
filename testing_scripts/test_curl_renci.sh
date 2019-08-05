#!/bin/bash
TEST_URL="https://dp-dev-1.cyberimpact.us/"
KEY=key.pem
CERT=cert.pem

curl -v -L -c cookie_file --data "ImPACT-JWT=${IMPACT_JWT}" --key "${KEY}" --cert "${CERT}" "${TEST_URL}"
