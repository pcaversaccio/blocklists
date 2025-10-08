# Blocklists

[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue)](https://www.gnu.org/licenses/agpl-3.0)

A Python script [`blocklist.py`](./scripts/blocklist.py) designed to retrieve comprehensive domain status reports from multiple blocklist providers.

```console
usage: blocklist.py [-h] -d DOMAINS

Check domains against all supported blocklist provider APIs.

options:
  -h, --help            show this help message and exit
  -d DOMAINS, --domains DOMAINS
                        comma-separated list of domains to check (e.g., "https://domain1.com,www.domain2.com,app.domain2.com")
```

## Prerequisites

- Python `>=3.6`
- API keys for the blocklist service providers

1. Clone this repository:

```console
git clone https://github.com/pcaversaccio/blocklists.git
cd blocklists
```

2. Create a virtual environment (optional but recommended):

```console
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`.
```

3. Install the required packages:

```console
pip install -r requirements.txt
```

4. Create a `.env` file in the project root and add your API keys for the blocklist service providers:

```txt
BLOWFISH_API_KEY="YOUR_BLOWFISH_API_KEY"
CHAINPATROL_API_KEY="YOUR_CHAINPATROL_API_KEY"
SCAMSNIFFER_IDENTIFIER="YOUR_SCAMSNIFFER_IDENTIFIER"
SCAMSNIFFER_API_KEY="YOUR_SCAMSNIFFER_API_KEY"
SEAL_ISAC_API_KEY="YOUR_SEAL_ISAC_API_KEY"
```

> [!CAUTION]
> Make sure to keep your `.env` file secure and _never_ commit it to version control!

## Usage

Run the script using Python:

```console
python scripts/blocklist.py --domains "walietconnect.events,www.kyberswap.org,https://ethena.fi,docs.vyperlang.org/en/stable"
```

## Supported Blocklist Providers

- [Blowfish](https://blowfish.xyz)
- [ChainPatrol](https://chainpatrol.io)
- [Scam Sniffer](https://www.scamsniffer.io)
- [MetaMask](https://github.com/MetaMask/eth-phishing-detect)
- [SEAL-ISAC](https://sealisac.org)
