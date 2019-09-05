#!/bin/bash

#set -x


# Constants
#
DEFAULT_VAULT_URL="http://127.0.0.1:8200"
DEFAULT_ADMIN_USERNAME="admin"
_HTTP_RET_CODE_LABEL="HTTP return code:"

# arguments
VAULT_URL=$1
ADMIN_USERNAME=$2

# Usage
if [[ "$1" == "h" || "$1" == "help" || "$1" == "--help" ]]; then
	echo "Usage: $0 <Vault URL> <admin username>"
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
	echo "Enter the password for \"$ADMIN_USERNAME\" to login:"
	read -s LOGINPASSWD

	ret=$(curl -SsL \
		-X POST \
		-d "{ \"password\" : \"$LOGINPASSWD\" }" \
		"$VAULT_URL/v1/auth/userpass/login/$ADMIN_USERNAME" \
	)

	if [[ $ret == *"invalid username or password"* ]]; then
		echo "Error.  Invalid username or password"
	else
		client_token=$(echo $ret | jq -r '.auth.client_token')
		echo "Login successfully, client Token: $client_token"
		echo "Using the login token now..."
		VAULT_TOKEN=$client_token
	fi
}

show_policies() {
	echo "Show policy"

	ret=$(curl -SsL \
		-H "X-Vault-Token: $VAULT_TOKEN" \
		-X GET \
		"$VAULT_URL/v1/auth/userpass/users/$ADMIN_USERNAME" \
	)

	#echo $ret

	policies=$(echo $ret | cut -d "[" -f2 | cut -d "]" -f1)

	echo $policies
}

display_a_policy() {
	echo "Display a policy"
	read -p "Enter the policy name: " polname

	ret=$(curl -SsL \
		-H "X-Vault-Token: $VAULT_TOKEN" \
		-X GET \
		"$VAULT_URL/v1/sys/policy/$polname" \
	)

	rules=$(echo $ret | jq -r '.rules')
	printf "%s\n" $rules
}

hmac_sha256() {
	echo "calculate hmac-sha256"
	read -p "Enter the audit path: " auditpath
	read -p "Enter the string to calculate hmac-sha256: " inputstring

	ret=$(curl -SsL \
		-H "X-Vault-Token: $VAULT_TOKEN" \
		-X POST \
		-d "{ \"input\" : \"$inputstring\" }" \
		"$VAULT_URL/v1/sys/audit-hash/$auditpath" \
	)

	hmac_sha256_val=$(echo $ret | jq -r '.hash')

	echo $hmac_sha256_val
}

enable_audit_file() {
	echo "Enable audit file"
	read -p "Enter the audit path (name of audit): " auditpath
	read -p "Enter the audit file path: " auditfilepath

	ret=$(curl -SsL \
		-H "X-Vault-Token: $VAULT_TOKEN" \
		-X PUT \
		-d "{\"type\":\"file\",\"options\":{\"file_path\":\"$auditfilepath\"}}" \
		"$VAULT_URL/v1/sys/audit/$auditpath" \
	)

	if [[ $ret != "" ]]; then
		echo "Error in enabling audit -file"
		echo $ret
	fi
}


disable_audit_file() {
	echo "Disable audit file"
	read -p "Enter the audit path (name of audit): " auditpath

	ret=$(curl -SsL \
		-H "X-Vault-Token: $VAULT_TOKEN" \
		-X DELETE \
		"$VAULT_URL/v1/sys/audit/$auditpath" \
	)

	if [[ $ret != "" ]]; then
		echo "Error in enabling audit -file"
		echo $ret
	fi
}

list_file_audit()
{
	echo "List file audits"
	
	ret=$(curl -SsL \
		-H "X-Vault-Token: $VAULT_TOKEN" \
		"$VAULT_URL/v1/sys/audit" \
	)

	echo $ret | jq
}

# inputs
PS3='Please enter your choice: '
options=("Login" "Change User's Password" "List Users" "Show policies" \
	 "Display a policy" "List file audits" "Enable audit file" \
	 "Disable audit file" "Calculate hmac-sha256" "Quit")
select opt in "${options[@]}"
do
	case $opt in
		"Login")
			login
			;;
		"Change User's Password")
			change_password
			;;
		"List Users")
			list_users
			;;
		"Show policies")
			show_policies
			;;
		"Display a policy")
			display_a_policy
			;;
		"List file audits")
			list_file_audit
			;;
		"Enable audit file")
			enable_audit_file
			;;
		"Disable audit file")
			disable_audit_file
			;;
		"Calculate hmac-sha256")
			hmac_sha256
			;;
		"Quit")
			break
			;;
		*) echo "invalid option $REPLY";;
	esac
done
