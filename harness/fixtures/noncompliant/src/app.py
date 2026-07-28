"""Non-compliant example: hardcoded, long-lived credentials in source."""
import requests

# Anti-pattern: static cloud credentials committed to source control.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_EXAMPLE0123456789abcdefABCDEF01234567"
client_secret = "abcd1234-EXAMPLE-client-secret-value-9876"


def call_api():
    return requests.get(
        "https://api.example/data",
        headers={"Authorization": f"token {GITHUB_TOKEN}"},
        verify=False,  # disables TLS verification — anti-pattern
    )
