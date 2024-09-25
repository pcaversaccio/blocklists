# References:
# - Blowfish: https://docs.blowfish.xyz/reference/scan-domain-1,
# - ChainPatrol: https://chainpatrol.io/docs/introduction.
import os, requests
from dotenv import load_dotenv

load_dotenv()

# URLs
URL_BLOWFISH = "https://api.blowfish.xyz/v0/domains"
URL_CHAINPATROL = "https://app.chainpatrol.io/api/v2/asset/check"

# Payloads
payload_blowfish = {"domains": ["https://walietconnect.events", "https://ethena.fi"]}
payload_chainpatrol = {"content": "https://walietconnect.events"}


# Headers
def get_headers(api_key_env, version=None):
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": os.getenv(api_key_env),
    }
    if version:
        headers["X-Api-Version"] = version
    return headers


headers_blowfish = get_headers("BLOWFISH_API_KEY", "2023-06-05")
headers_chainpatrol = get_headers("CHAINPATROL_API_KEY")

response_blowfish = requests.post(
    URL_BLOWFISH, json=payload_blowfish, headers=headers_blowfish
)
response_chainpatrol = requests.post(
    URL_CHAINPATROL, json=payload_chainpatrol, headers=headers_chainpatrol
)

# Print responses
for name, response in [
    ("Blowfish", response_blowfish),
    ("ChainPatrol", response_chainpatrol),
]:
    print(f"{name}:\n---------\n{response.text}\n")
