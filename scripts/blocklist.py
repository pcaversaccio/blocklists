# References:
# - Blowfish: https://docs.blowfish.xyz/reference/scan-domain-1,
# - ChainPatrol: https://chainpatrol.io/docs/external-api/asset-check,
# - Scam Sniffer: https://docs.scamsniffer.io/reference/getsitecheck.

import os, requests, argparse
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

# ANSI escape code for the green and default colour.
GREEN = "\033[92m"
RESET = "\033[0m"

# Specify the API endpoints for the blocklist service providers.
URL_BLOWFISH = "https://api.blowfish.xyz/v0/domains"
URL_CHAINPATROL = "https://app.chainpatrol.io/api/v2/asset/check"
URL_SCAMSNIFFER = "https://lookup-api.scamsniffer.io/site/check"


# Helper function to construct the request headers for the API calls.
def get_headers(api_key_env, version=None):
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": os.getenv(api_key_env),
    }
    if version:
        headers["X-Api-Version"] = version
    return headers


# Helper function to send the Blowfish request.
def send_blowfish_request(domains):
    # Extract the host names from the domains.
    hostnames = ["https://" + urlparse(domain).hostname.lower() for domain in domains]
    payload_blowfish = {"domains": hostnames}
    headers_blowfish = get_headers("BLOWFISH_API_KEY", "2023-06-05")
    response_blowfish = requests.post(
        URL_BLOWFISH, json=payload_blowfish, headers=headers_blowfish
    )
    return response_blowfish


# Helper function to send the ChainPatrol request (one domain at a time).
def send_chainpatrol_request(domain):
    # Extract the hostname from the domain.
    parsed_url = urlparse(domain)
    hostname = parsed_url.hostname.lower()
    payload_chainpatrol = {"content": hostname}
    headers_chainpatrol = get_headers("CHAINPATROL_API_KEY")
    response_chainpatrol = requests.post(
        URL_CHAINPATROL, json=payload_chainpatrol, headers=headers_chainpatrol
    )
    return response_chainpatrol


# Helper function to send the Scam Sniffer request (one domain at a time).
def send_scamsniffer_request(domain):
    # Extract the hostname from the domain.
    parsed_url = urlparse(domain)
    hostname = parsed_url.hostname.lower()
    url_scamsniffer = f"{URL_SCAMSNIFFER}?url={hostname}"
    headers_scamsniffer = {
        "Accept": "*/*",
        "X-Api-Key": os.getenv("SCAMSNIFFER_API_KEY"),
    }
    response_scamsniffer = requests.get(url_scamsniffer, headers=headers_scamsniffer)
    return response_scamsniffer


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

    # Send the Blowfish API call.
    blowfish_response = send_blowfish_request(domains)
    blowfish_data = blowfish_response.json()

    print(f"{GREEN}Blowfish:{RESET}\n---------")

    # Loop through the response and print the domain name and risk score.
    for domain_info in blowfish_data:
        domain = domain_info.get("domain", "Unknown domain")
        status = domain_info.get("status", "Unknown status")
        risk_score = domain_info.get("riskScore", "No risk score")

        # Check if the domain is processed.
        if status == "PROCESSED":
            print(f"Domain: {domain}\nRisk Score: {risk_score}\n")
        else:
            print(f"Domain: {domain}\nStatus: {status}\n")

    chainpatrol_results = []
    scamsniffer_results = []

    for domain in domains:
        domain_hostname = urlparse(domain).hostname.lower()

        # Send the ChainPatrol API call (one request per domain).
        chainpatrol_response = send_chainpatrol_request(domain)
        chainpatrol_status = chainpatrol_response.json().get(
            "status", "Status not found"
        )

        # Store the ChainPatrol result.
        chainpatrol_results.append((domain_hostname, chainpatrol_status))

        # Send the Scam Sniffer API call for each domain.
        scamsniffer_response = send_scamsniffer_request(domain)
        scamsniffer_status = scamsniffer_response.json().get(
            "status", "Status not found"
        )

        # Store the Scam Sniffer result.
        scamsniffer_results.append((domain_hostname, scamsniffer_status))

    # Print the results for ChainPatrol.
    print(f"{GREEN}ChainPatrol Results:{RESET}\n")
    for domain_hostname, status in chainpatrol_results:
        print(f"Domain: {domain_hostname}\nStatus: {status}\n")

    # Print the results for Scam Sniffer.
    print(f"{GREEN}Scam Sniffer Results:{RESET}\n")
    for domain_hostname, status in scamsniffer_results:
        print(f"Domain: {domain_hostname}\nStatus: {status}\n")


if __name__ == "__main__":
    main()
