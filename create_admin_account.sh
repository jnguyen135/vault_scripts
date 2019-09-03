#!/bin/bash

#set -x

# Constants
#
DEFAULT_VAULT_URL="http://127.0.0.1:8200"
DEFAULT_ADMIN_POLICY_FILENAME="admin-policy.hcl"
DEFAULT_ADMIN_POLICY_NAME="admins"
DEFAULT_ADMIN_USERNAME="admin"
DEFAULT_ADMIN_PASSWORD="password"
_HTTP_RET_CODE_LABEL="HTTP return code:"

# inputs
VAULT_TOKEN=$1
VAULT_URL=$2
ADMIN_POLICY_FILENAME=$3
ADMIN_POLICY_NAME=$4
ADMIN_USERNAME=$5
ADMIN_PASSWORD=$6

# Usage
if [[ "$1" == "h" || "$1" == "help" || " $1" == "--help" || -z "$VAULT_TOKEN" || "$VAULT_TOKEN" == "." ]]; then
	echo "Usage: $0 <Vault Token> <Vault URL> <admin policy filename> <admin policy name> <admin username> <admin password>"
	echo "       Use . for the default value for any parameter but the 2nd argument <Vault Token> must be specified"
	exit 1
fi

if [[ -z "$VAULT_URL" || "$VAULT_URL" == "." ]]; then
	VAULT_URL=$DEFAULT_VAULT_URL
	echo "Set to default admin username: $VAULT_URL"
else
	echo "VAULT_URL = $VAULT_URL"
fi

if [[ -z "$ADMIN_POLICY_FILENAME" || "$ADMIN_POLICY_FILENAME" == "." ]]; then
	ADMIN_POLICY_FILENAME=$DEFAULT_ADMIN_POLICY_FILENAME
	echo "Set to default admin policy filename: $ADMIN_POLICY_FILENAME"
else
	echo "ADMIN_POLICY_FILENAME = $ADMIN_POLICY_FILENAME"
fi
if [[ ! -f "$ADMIN_POLICY_FILENAME" ]]; then
	echo "Error! file $ADMIN_POLICY_FILENAME does not exist"
	exit 2
fi

if [[ -z "$ADMIN_POLICY_NAME" || "$ADMIN_POLICY_NAME" == "." ]]; then
	ADMIN_POLICY_NAME=$DEFAULT_ADMIN_POLICY_NAME
	echo "Set to default admin policy name: $ADMIN_POLICY_NAME"
else
	echo "ADMIN_POLICY_NAME = $ADMIN_POLICY_NAME"
fi

if [[ -z "$ADMIN_USERNAME" || "$ADMIN_USERNAME" == "." ]]; then
	ADMIN_USERNAME=$DEFAULT_ADMIN_USERNAME
	echo "Set to default admin username: $ADMIN_USERNAME"
else
	echo "ADMIN_USERNAME = $ADMIN_USERNAME"
fi

if [[ -z "$ADMIN_PASSWORD" || "$ADMIN_PASSWORD" == "." ]]; then
	ADMIN_PASSWORD=$DEFAULT_ADMIN_PASSWORD
	echo "Set to default admin password"
fi

# Install requirements
if [ ! -f /usr/local/bin/json2hcl ]; then
	echo "Error! Please install json to hcl (json2hcl) utility"	
	exit 3
fi

# 1) Enable LOCAL authentication
echo "Enable LOCAL authentication"
ret=$(curl -SsL \
	-H "X-Vault-Token: $VAULT_TOKEN" \
	-X POST \
	-d '{"type" : "userpass" }' \
	-w "$_HTTP_RET_CODE_LABEL %{http_code}\n" \
	"$VAULT_URL/v1/sys/auth/userpass" \
	-k \
)

if [[ $ret == *"$_HTTP_RET_CODE_LABEL 2"* || $ret ==  *"path is already in use at userpass/"* ]]; then
	echo "LOCAL authentication enabled"
else
	echo "Error in enabling LOCAL authentication: "
	echo $ret
	exit 4
fi

# 2) Create the admin policy

# 2.1) Use vault to compose the curl command with the hcl policy
curlpolcmd=$(vault policy write -output-curl-string $ADMIN_POLICY_NAME $ADMIN_POLICY_FILENAME)
curlpolcmd2="${curlpolcmd/'$(vault print token)'/$VAULT_TOKEN} -SsL -w \"$_HTTP_RET_CODE_LABEL %{http_code}\n\" -k"

echo "Create admin policy"
ret=$(eval $curlpolcmd2)

if [[ $ret == *"$_HTTP_RET_CODE_LABEL 2"* ]]; then
	echo "admin policy created"
else
	echo "Error in creating admin policy: "
	echo $ret
	exit 5
fi

# 3) Create an admin local account with admin policy
echo "Create a local admin user with admin policy"
ret=$(curl --silent --location \
	--header "X-Vault-Token: $VAULT_TOKEN" \
	--header "Content-Type: application/json" \
	--request POST "$VAULT_URL/v1/auth/userpass/users/$ADMIN_USERNAME" \
	--insecure \
	--data "{ \"password\": \"$ADMIN_PASSWORD\", \
		  \"policies\": \"$ADMIN_POLICY_NAME,default\" }" \
	--write-out "$_HTTP_RET_CODE_LABEL %{http_code}\n" \
)

if [[ $ret == "$_HTTP_RET_CODE_LABEL 2"* ]]; then
	echo "local admin user created"
else
	echo "Error in creating local admin user: "
	echo $ret
	exit 6
fi
