# References:
# - Blowfish: https://docs.blowfish.xyz/reference/scan-domain-1,
# - ChainPatrol: https://chainpatrol.io/docs/external-api/asset-check,
# - Scam Sniffer: https://docs.scamsniffer.io/reference/getsitecheck,
# - MetaMask: https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/refs/heads/main/src/config.json,
# - SEAL-ISAC: https://github.com/OpenCTI-Platform/client-python.

import os, requests, argparse, urllib3, logging
from urllib.parse import urlparse
from dotenv import load_dotenv
from pycti import OpenCTIApiClient


load_dotenv()


# Disable the SSL warnings from SEAL-ISAC.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set the root logger's level to "WARNING" to suppress "INFO" logs globally.
logging.basicConfig(level=logging.WARNING)
# Set logging level for `pycti` to "WARNING" to suppress "INFO" logs specifically.
logging.getLogger("pycti").setLevel(logging.WARNING)


# ANSI escape codes for the colours.
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

# Specify the API endpoints for the blocklist service providers.
URL_BLOWFISH = "https://api.blowfish.xyz/v0/domains"
URL_CHAINPATROL = "https://app.chainpatrol.io/api/v2/asset/check"
URL_SCAMSNIFFER = "https://lookup-api.scamsniffer.io/site/check"
URL_METAMASK = "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/refs/heads/main/src/config.json"
URL_SEAL_ISAC = "https://sealisac.org"


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


# Helper function to check the MetaMask blacklist.
def check_metamask_blacklist(domain):
    response = requests.get(URL_METAMASK)
    blacklist = response.json().get("blacklist", [])
    domain_hostname = urlparse(domain).hostname.lower()
    return domain_hostname in blacklist


# Helper function to check the SEAL-ISAC blacklist.
def check_seal_isac_blacklist(domain):
    opencti_api_client = OpenCTIApiClient(
        url=URL_SEAL_ISAC, token=os.getenv("SEAL_ISAC_API_KEY"), ssl_verify=False
    )
    domain_hostname = urlparse(domain).hostname.lower()
    try:
        query = """
        query DomainObservables($domain: String!) {
          stixCyberObservables(search: $domain) {
            edges {
              node {
                id
                entity_type
                objectLabel {
                  value
                }
                observable_value
              }
            }
          }
        }
        """
        variables = {"domain": domain_hostname}
        result = opencti_api_client.query(query, variables)
        observables = result["data"]["stixCyberObservables"]["edges"]

        # Check if any observable has "blocklisted domain" as the `objectLabel` value.
        for obs in observables:
            observable_value = obs["node"].get("observable_value", "").lower()
            labels = obs["node"].get("objectLabel", [])
            if observable_value == domain_hostname and any(
                label["value"] == "blocklisted domain" for label in labels
            ):
                return True
        return False
    except Exception as e:
        print(f"{RED}Failed to query SEAL-ISAC: {str(e)}{RESET}")
        return False


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

    print(f"{GREEN}Blowfish Results:{RESET}\n-----------------")

    # Loop through the response and print the domain name and risk score.
    for domain_info in blowfish_data:
        domain = domain_info.get("domain", "Unknown domain")
        status = domain_info.get("status", "Unknown status")
        risk_score = domain_info.get("riskScore", "No risk score")

        # Check if the risk score is `>= 0.5` and print in red if true.
        if isinstance(risk_score, (int, float)) and risk_score >= 0.5:
            risk_score_output = f"{RED}{risk_score}{RESET}"
        else:
            risk_score_output = risk_score

        # Print the status. If it's "BLOCKED", print in red.
        if status == "BLOCKED":
            status_output = f"{RED}{status}{RESET}"
        else:
            status_output = status

        # Check if the domain is processed.
        if status == "PROCESSED":
            print(f"Domain: {domain}\nRisk Score: {risk_score_output}\n")
        else:
            print(f"Domain: {domain}\nStatus: {status_output}\n")

    chainpatrol_results = []
    scamsniffer_results = []
    metamask_results = []
    seal_isac_results = []

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

        # Check MetaMask for blacklisting.
        is_phishing = check_metamask_blacklist(domain)
        metamask_status = "BLOCKED" if is_phishing else "ALLOWED"
        metamask_results.append((domain_hostname, metamask_status))

        # Check SEAL-ISAC for blacklisting.
        is_blacklisted = check_seal_isac_blacklist(domain)
        seal_isac_status = "BLOCKED" if is_blacklisted else "ALLOWED"
        seal_isac_results.append((domain_hostname, seal_isac_status))

    # Print the results for ChainPatrol.
    print(f"{GREEN}ChainPatrol Results:{RESET}\n--------------------")
    for domain_hostname, status in chainpatrol_results:
        if status == "BLOCKED":
            status_output = f"{RED}{status}{RESET}"
        else:
            status_output = status

        print(f"Domain: {domain_hostname}\nStatus: {status_output}\n")

    # Print the results for Scam Sniffer.
    print(f"{GREEN}Scam Sniffer Results:{RESET}\n---------------------")
    for domain_hostname, status in scamsniffer_results:
        if status == "BLOCKED":
            status_output = f"{RED}{status}{RESET}"
        else:
            status_output = status

        print(f"Domain: {domain_hostname}\nStatus: {status_output}\n")

    # Print the results for MetaMask.
    print(f"{GREEN}MetaMask Results:{RESET}\n-----------------")
    for domain_hostname, status in metamask_results:
        if status == "BLOCKED":
            status_output = f"{RED}{status}{RESET}"
        else:
            status_output = status

        print(f"Domain: {domain_hostname}\nStatus: {status_output}\n")

    # Print the results for SEAL-ISAC.
    print(f"{GREEN}SEAL-ISAC Results:{RESET}\n------------------")
    for domain_hostname, status in seal_isac_results:
        if status == "BLOCKED":
            status_output = f"{RED}{status}{RESET}"
        else:
            status_output = status

        print(f"Domain: {domain_hostname}\nStatus: {status_output}\n")


if __name__ == "__main__":
    main()
