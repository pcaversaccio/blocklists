# Blocklists

[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue)](https://www.gnu.org/licenses/agpl-3.0)

A Python script [`blocklist.py`](./scripts/blocklist.py) designed to retrieve comprehensive domain status reports from multiple blocklist providers.

```console
usage: blocklist.py [-h] -d DOMAINS

Check domains against all supported blocklist provider APIs.

options:
  -h, --help            show this help message and exit
  -d DOMAINS, --domains DOMAINS
                        comma-separated list of domains to check (e.g., "https://domain1.com,https://domain2.com")
```

## Usage

First, install the required packages:

```console
pip install -r requirements.txt
```

**Example:**

```console
python scripts/blocklist.py --domains "https://walietconnect.events,https://ethena.fi"
```

## Supported Blocklist Providers

- [Blowfish](https://blowfish.xyz)
- [ChainPatrol](https://chainpatrol.io)
