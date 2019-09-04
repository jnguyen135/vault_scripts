#!/bin/bash

#set -x


# Constants
#
DEFAULT_VAULT_URL="http://127.0.0.1:8200"
DEFAULT_ADMIN_USERNAME="admin"
_HTTP_RET_CODE_LABEL="HTTP return code:"

# arguments
VAULT_TOKEN=$1
VAULT_URL=$2
ADMIN_USERNAME=$3

# Usage
if [[ "$1" == "h" || "$1" == "help" || "$1" == "--help" || -z "$VAULT_TOKEN" ]]; then
	echo "Usage: $0 <Vault Token> <Vault URL> <admin username>"
	echo "       Use . for the default value for any parameter but the 1st argument <Vault Token> must be specified"
	exit 1
fi

if [[ -z "$VAULT_URL" || "$VAULT_URL" == "." ]]; then
	VAULT_URL=$DEFAULT_VAULT_URL
	echo "Set the default Vault URL to $VAULT_URL"
else
	echo "VAULT_URL = $VAULT_URL"
fi

if [[ -z "$ADMIN_USERNAME" || "$ADMIN_USERNAME" == "." ]]; then
	ADMIN_USERNAME=$DEFAULT_ADMIN_USERNAME
	echo "Set the default admin user to $ADMIN_USERNAME"
else
	echo "ADMIN_USERNAME = $ADMIN_USERNAME"
fi

list_users() {
	echo "List Users"
	ret=$(curl -SsL \
		-H "X-Vault-Token: $VAULT_TOKEN" \
		-X LIST \
		"$VAULT_URL/v1/auth/userpass/users" \
	)

	#echo $ret

	users=$(echo $ret | cut -d "[" -f2 | cut -d "]" -f1)

	echo $users
}

change_password() {
	echo "Change User's Password"
	echo "Enter the new password for $ADMIN_USERNAME user:"
	read -s PASSWD

	ret=$(curl -SsL \
		-H "X-Vault-Token: $VAULT_TOKEN" \
		-X POST \
		-d "{ \"password\" : \"$PASSWD\" }" \
		-w "$_HTTP_RET_CODE_LABEL %{http_code}\n" \
		"$VAULT_URL/v1/auth/userpass/users/$ADMIN_USERNAME/password" \
	)

	if [[ $ret == *"$_HTTP_RET_CODE_LABEL 2"* ]]; then
		echo "Password changed successfully"
	else
		echo "Error! Failed to change password:"
		echo $ret
	fi
}

login() {
	echo "Login"
	echo "Enter the password for $ADMIN_USER to login:"
	read -s LOGINPASSWD

	ret=$(curl -SsL \
		-H "X-Vault-Token: $VAULT_TOKEN" \
		-X POST \
		-d "{ \"password\" : \"$LOGINPASSWD\" }" \
		"$VAULT_URL/v1/auth/userpass/login/$ADMIN_USERNAME" \
	)

	if [[ $ret == *"invalid username or password"* ]]; then
		echo "Error.  Invalid username or password"
	else
		client_token=$(echo $ret | jq -r '.auth.client_token')
		echo "Login successfully, client Token: $client_token"
	fi
}

# inputs
PS3='Please enter your choice: '
options=("List Users" "Change User's Password" "Login" "Quit")
select opt in "${options[@]}"
do
	case $opt in
		"List Users")
			list_users
			;;
		"Change User's Password")
			change_password
			;;
		"Login")
			login
			;;
		"Quit")
			break
			;;
		*) echo "invalid option $REPLY";;
	esac
done
