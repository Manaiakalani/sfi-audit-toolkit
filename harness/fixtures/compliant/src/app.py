"""Compliant example: managed identity + Key Vault, no secrets in source."""
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Workload identity — no client secret in code; token is short-lived.
credential = DefaultAzureCredential()
client = SecretClient(
    vault_url="https://kv-contoso-prod.vault.azure.net/",
    credential=credential,
)


def get_db_password() -> str:
    # Secret is retrieved at runtime from a hardened vault, never committed.
    return client.get_secret("db-password").value
