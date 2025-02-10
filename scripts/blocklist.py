#!/usr/bin/env python

# API References:
# ---------------
# - Blowfish: https://docs.blowfish.xyz/reference/scan-domain-1,
# - ChainPatrol: https://chainpatrol.io/docs/external-api/asset-check,
# - Scam Sniffer: https://docs.scamsniffer.io/reference/getsitecheck,
# - MetaMask: https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/refs/heads/main/src/config.json,
# - SEAL-ISAC: https://github.com/OpenCTI-Platform/client-python.

import os, requests, argparse, urllib3, logging
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import List, Dict, Optional
from dotenv import load_dotenv
from pycti import OpenCTIApiClient


load_dotenv()


# Disable the SSL warnings from SEAL-ISAC.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set the root logger's level to "WARNING" to suppress "INFO" logs globally.
logging.basicConfig(level=logging.WARNING)


class Colours:
    """Sets the ANSI escape codes for the colours."""

    GREEN = "\033[92m"
    RED = "\033[91m"
    RESET = "\033[0m"


class APIEndpoints:
    """Sets the API endpoints for the blocklist service providers."""

    BLOWFISH = "https://api.blowfish.xyz/v0/domains"
    CHAINPATROL = "https://app.chainpatrol.io/api/v2/asset/check"
    SCAMSNIFFER = "https://lookup-api.scamsniffer.io/site/check"
    METAMASK = "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/refs/heads/main/src/config.json"
    SEAL_ISAC = "https://sealisac.org"


@dataclass
class DomainCheck:
    """Represents the result of a domain check."""

    domain: str
    status: str
    risk_score: Optional[float] = None
    error: Optional[str] = None


class DomainChecker:
    """Handles all domain checks."""

    def __init__(self):
        self.metamask_blacklist = None

    def normalise_domain(self, domain: str, include_scheme: bool = False) -> str:
        """Normalises a domain by ensuring a proper format and lower case."""
        parsed = urlparse(
            domain
            if domain.startswith(("http://", "https://"))
            else f"https://{domain}"
        )
        if parsed.hostname is None:
            raise ValueError(f"Invalid domain: '{domain}'")
        # The Python function `urlparse` ensures that the hostname is in lower case.
        # See: https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlparse.
        hostname = parsed.hostname
        return f"https://{hostname}" if include_scheme else hostname

    def get_headers(
        self, api_key_env: str, version: Optional[str] = None
    ) -> Dict[str, str]:
        """Constructs the headers for the API requests."""
        headers = {
            "Content-Type": "application/json",
            "X-Api-Key": os.getenv(api_key_env),
        }
        if version:
            headers["X-Api-Version"] = version
        return headers

    def check_blowfish(self, domains: List[str]) -> List[DomainCheck]:
        """Checks the domains against the Blowfish API."""
        try:
            hostnames = [self.normalise_domain(domain, True) for domain in domains]
            response = requests.post(
                APIEndpoints.BLOWFISH,
                json={"domains": hostnames},
                headers=self.get_headers("BLOWFISH_API_KEY", "2023-06-05"),
            )
            response.raise_for_status()
            results = []
            for domain_info in response.json():
                results.append(
                    DomainCheck(
                        domain=domain_info.get("domain", "Unknown domain"),
                        status=domain_info.get("status", "Unknown status"),
                        risk_score=domain_info.get("riskScore", "No risk score"),
                    )
                )
            return results
        except Exception as e:
            return [
                DomainCheck(domain=d, status="ERROR", error=str(e)) for d in domains
            ]

    def check_chainpatrol(self, domain: str) -> DomainCheck:
        """Checks the domain against the ChainPatrol API."""
        try:
            hostname = self.normalise_domain(domain)
            response = requests.post(
                APIEndpoints.CHAINPATROL,
                json={"content": hostname},
                headers=self.get_headers("CHAINPATROL_API_KEY"),
            )
            response.raise_for_status()
            return DomainCheck(
                domain=hostname,
                status=response.json().get("status", "Unknown status"),
            )
        except Exception as e:
            return DomainCheck(domain=hostname, status="ERROR", error=str(e))

    def check_scamsniffer(self, domain: str) -> DomainCheck:
        """Checks the domain against the Scam Sniffer API."""
        try:
            hostname = self.normalise_domain(domain)
            response = requests.get(
                f"{APIEndpoints.SCAMSNIFFER}?url={hostname}",
                headers={
                    "Accept": "*/*",
                    "X-Api-Key": os.getenv("SCAMSNIFFER_API_KEY"),
                },
            )
            response.raise_for_status()
            return DomainCheck(
                domain=hostname,
                status=response.json().get("status", "Unknown status"),
            )
        except Exception as e:
            return DomainCheck(domain=hostname, status="ERROR", error=str(e))

    def check_metamask(self, domain: str) -> DomainCheck:
        """Checks the domain against the MetaMask blacklist."""
        try:
            hostname = self.normalise_domain(domain)
            if not self.metamask_blacklist:
                response = requests.get(APIEndpoints.METAMASK)
                response.raise_for_status()
                self.metamask_blacklist = set(response.json().get("blacklist", []))

            status = "BLOCKED" if hostname in self.metamask_blacklist else "ALLOWED"
            return DomainCheck(domain=hostname, status=status)
        except Exception as e:
            return DomainCheck(domain=hostname, status="ERROR", error=str(e))

    def check_seal_isac(self, domain: str) -> DomainCheck:
        """Checks the domain against the SEAL-ISAC blacklist."""
        try:
            hostname = self.normalise_domain(domain)
            client = OpenCTIApiClient(
                url=APIEndpoints.SEAL_ISAC, token=os.getenv("SEAL_ISAC_API_KEY")
            )

            # See https://docs.opencti.io/latest/usage/exploring-observations/#observables.
            observable_filters = {
                "mode": "and",
                "filters": [{"key": "value", "values": [hostname]}],
                "filterGroups": [],
            }
            observable = client.stix_cyber_observable.read(filters=observable_filters)

            # Please note that the labels `allowlisted domain` and `blocklisted domain`
            # have been deprecated. See: https://github.com/security-alliance/seal-isac-sdk.js/blob/c349394eb2d82058e90ea634f5a3dd0647fbf6c5/src/web-content/types.ts#L3-L10.
            if observable:
                labels = {label["value"] for label in observable.get("objectLabel", [])}
                if any(
                    l in labels for l in ["allowlisted domain", "trusted web content"]
                ):
                    return DomainCheck(domain=hostname, status="TRUSTED")
                if "blocklisted domain" in labels:
                    return DomainCheck(domain=hostname, status="BLOCKED")

            # See https://docs.opencti.io/latest/usage/exploring-observations/#indicators.
            indicator_filters = {
                "mode": "and",
                "filters": [
                    {
                        "key": "pattern",
                        "values": [f"[domain-name:value = '{hostname}']"],
                    }
                ],
                "filterGroups": [],
            }
            indicator = client.indicator.read(filters=indicator_filters)

            if indicator:
                return DomainCheck(
                    domain=hostname,
                    status=(
                        "BLOCKED" if not indicator.get("revoked", False) else "UNKNOWN"
                    ),
                )

            return DomainCheck(domain=hostname, status="UNKNOWN")
        except Exception as e:
            return DomainCheck(domain=hostname, status="ERROR", error=str(e))


def print_results(title: str, results: List[DomainCheck]):
    """Prints the results in a consistent format."""
    print(f"{Colours.GREEN}{title}:{Colours.RESET}\n{'-' * (len(title) + 1)}")
    for result in results:
        status_output = (
            f"{Colours.RED}{result.status}{Colours.RESET}"
            if result.status in ["BLOCKED", "ERROR"]
            else result.status
        )

        print(f"Domain: {result.domain}")
        if result.risk_score is not None:
            # Checks if the risk score is `>= 0.5` and prints in red if true.
            risk_score_output = (
                f"{Colours.RED}{str(result.risk_score)}{Colours.RESET}"
                if result.risk_score >= 0.5
                else str(result.risk_score)
            )
            print(f"Risk Score: {risk_score_output}")
            status_output = (
                f"{Colours.RED}BLOCKED{Colours.RESET}"
                if result.risk_score >= 0.5
                else status_output
            )
        print(f"Status: {status_output}")
        if result.error:
            print(f"Error: {Colours.RED}{result.error}{Colours.RESET}")
        print()


def parse_args():
    """Parses the command line arguments."""
    parser = argparse.ArgumentParser(
        description="Check domains against all supported blocklist provider APIs."
    )
    parser.add_argument(
        "-d",
        "--domains",
        required=True,
        help='comma-separated list of domains to check (e.g., "https://domain1.com,www.domain2.com,app.domain2.com")',
    )
    return parser.parse_args()


def check():
    """Runs all domain checks."""
    args = parse_args()
    domains = [domain.strip() for domain in args.domains.split(",")]
    checker = DomainChecker()

    blowfish_results = checker.check_blowfish(domains)
    chainpatrol_results = [checker.check_chainpatrol(domain) for domain in domains]
    scamsniffer_results = [checker.check_scamsniffer(domain) for domain in domains]
    metamask_results = [checker.check_metamask(domain) for domain in domains]
    seal_isac_results = [checker.check_seal_isac(domain) for domain in domains]

    print_results("Blowfish Results", blowfish_results)
    print_results("ChainPatrol Results", chainpatrol_results)
    print_results("Scam Sniffer Results", scamsniffer_results)
    print_results("MetaMask Results", metamask_results)
    print_results("SEAL-ISAC Results", seal_isac_results)


if __name__ == "__main__":
    check()
