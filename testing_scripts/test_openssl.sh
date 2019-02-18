#!/bin/bash
TEST_STRING="GET / HTTP/1.1\r\nHost:localhost\r\n\r\n"
TEST_HOST="localhost:8000"
KEY=key.pem
CERT=cert.pem
CAFILE=ca-certs.pem

echo -e "${TEST_STRING}" | openssl s_client -connect "${TEST_HOST}" -CAfile "${CAFILE}" -cert "${CERT}" -key "${KEY}" -ign_eof
