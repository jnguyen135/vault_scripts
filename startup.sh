#!/bin/bash

#set -x

# Constants
#
DEFAULT_VAULT_URL="http://127.0.0.1:8200"
_HTTP_RET_CODE_LABEL="HTTP return code:"
CONFIG_FILENAME=.vault.config

# inputs

# Usage
if [[ "$1" == "h" || "$1" == "help" || " $1" == "--help" ]]; then
	echo "Usage: $0 <Vault URL>"
	echo "       Use . for the default value at any parameter"
	exit 1
fi

if [[ -z "$VAULT_URL" || "$VAULT_URL" == "." ]]; then
	VAULT_URL=$DEFAULT_VAULT_URL
	echo "Set to default vault URL: $VAULT_URL"
else
	echo "VAULT_URL = $VAULT_URL"
fi

# 1) Check if system is initialized and init it
# 1.1) First read the status
ret=$(curl -SsL \
	"$VAULT_URL/v1/sys/seal-status" \
)

initialize=$(echo $ret | jq -r '.initialized')
sealed=$(echo $ret | jq -r '.sealed')

# 1.2) If vault has not been initialized, initialize it
if [[ $initialize == "false" ]]; then
	echo "Initializing vault"
	ret=$(curl -SsL \
		-X PUT \
		-d '{"secret_shares" : 1, "secret_threshold" : 1 }' \
		"$VAULT_URL/v1/sys/init" \
		-k \
	)

	echo $ret > $CONFIG_FILENAME
	echo "Vault has initialized. Config saved to $CONFIG_FILENAME"
fi

# 1.3) If vault was sealed, unseal it
if [[ $sealed == "true" ]]; then
	echo "Vault is sealed. Unsealing..."

	ret=$(cat $CONFIG_FILENAME | jq -r '.keys_base64')
	base64sealkey=$(echo $ret | cut -d "[" -f2 | cut -d "]" -f1)

	ret=$(curl -SsL \
		-X PUT \
		-d "{\"key\":$base64sealkey}" \
		$VAULT_URL/v1/sys/unseal \
		-w "$_HTTP_RET_CODE_LABEL %{http_code}\n" \
		-k \
	)

	if [[ $ret == *"$_HTTP_RET_CODE_LABEL 2"* ]]; then
		echo "Vault unsealed: "
		echo $ret
	else
		echo "Error in unsealing vault: "
		echo $ret
	fi
fi

# 2) Create an admin account with admin-policy.hcl
roottoken=$(cat $CONFIG_FILENAME | jq -r '.root_token')
./create_admin_account.sh $roottoken $VAULT_URL

# 3) Launch post account script
./post_admin_account.sh
