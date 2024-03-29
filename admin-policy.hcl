# admin must be able to:

# -Mount and manage auth backends broadly across Vault
# -Mount and manage secret backends broadly across Vault
# -Create and manage ACL policies broadly across Vault
# -Read system health check
# -Mount and manage audit devices broadly accross Vault
# -Calculate hmac-sha256 of strings to search for strings in the audit logs

# Manage auth backends broadly across Vault
path "auth/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# List, create, update, and delete auth backends
path "sys/auth/*"
{
  capabilities = ["create", "read", "update", "delete", "sudo"]
}

# To list policies - Step 3
path "sys/policy"
{
  capabilities = ["read"]
}

# Create and manage ACL policies broadly across Vault
path "sys/policy/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# List, create, update, and delete key/value secrets
path "secret/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Manage and manage secret backends broadly across Vault.
path "sys/mounts/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Read health checks
path "sys/health"
{
  capabilities = ["read", "sudo"]
}

# To perform Step 4
path "sys/capabilities"
{
  capabilities = ["create", "update"]
}

# To perform Step 4
path "sys/capabilities-self"
{
  capabilities = ["create", "update"]
}

# To list audits
path "sys/audit"
{
  capabilities = ["read", "sudo"]
}

# create and manage audit logs broadly across Vault
path "sys/audit/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# To calculate hmac-sha256
path "sys/audit-hash/*" {
  capabilities = ["create", "update"]
}
