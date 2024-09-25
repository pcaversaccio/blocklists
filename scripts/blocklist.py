import os, requests, argparse, json
from dotenv import load_dotenv

load_dotenv()

# ANSI escape code for the green and default colour.
GREEN = "\033[92m"
RESET = "\033[0m"

# Specify the API endpoints for the blocklist service providers.
URL_BLOWFISH = "https://api.blowfish.xyz/v0/domains"
URL_CHAINPATROL = "https://app.chainpatrol.io/api/v2/asset/check"


# Helper function to construct the request headers for the API calls.
def get_headers(api_key_env, version=None):
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": os.getenv(api_key_env),
    }
    if version:
        headers["X-Api-Version"] = version
    return headers


# Helper function to send Blowfish request.
def send_blowfish_request(domains):
    payload_blowfish = {"domains": domains}
    headers_blowfish = get_headers("BLOWFISH_API_KEY", "2023-06-05")
    response_blowfish = requests.post(
        URL_BLOWFISH, json=payload_blowfish, headers=headers_blowfish
    )
    return response_blowfish


# Helper function to send ChainPatrol request (one domain at a time).
def send_chainpatrol_request(domain):
    payload_chainpatrol = {"content": domain}
    headers_chainpatrol = get_headers("CHAINPATROL_API_KEY")
    response_chainpatrol = requests.post(
        URL_CHAINPATROL, json=payload_chainpatrol, headers=headers_chainpatrol
    )
    return response_chainpatrol


# Command-line argument parsing.
def parse_args():
    parser = argparse.ArgumentParser(
        description="Check domains against all supported blocklist provider APIs."
    )
    parser.add_argument(
        "-d",
        "--domains",
        required=True,
        help='comma-separated list of domains to check (e.g., "https://domain1.com,https://domain2.com")',
    )
    return parser.parse_args()


def main():
    args = parse_args()
    domains = [domain.strip() for domain in args.domains.split(",")]

    # Send Blowfish API call.
    blowfish_response = send_blowfish_request(domains)
    try:
        blowfish_data = blowfish_response.json()
        print(
            f"{GREEN}Blowfish:{RESET}\n---------\n"
            + json.dumps(blowfish_data, indent=2)
        )
    except ValueError:
        print(f"{GREEN}Blowfish:{RESET}\n---------\n" + blowfish_response.text)

    # Send ChainPatrol API call (one request per domain).
    for domain in domains:
        chainpatrol_response = send_chainpatrol_request(domain)
        print(
            f"{GREEN}ChainPatrol ({domain}):{RESET}\n---------\n{chainpatrol_response.text}\n"
        )


if __name__ == "__main__":
    main()
