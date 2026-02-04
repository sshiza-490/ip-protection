# IP Protection Reference Implementation

This directory contains a reference implementation of the IP Protection concepts described in the Chrome IP Protection proposal.

## Overview

The IP Protection module provides a Python implementation that demonstrates the core concepts:

- **Masked Domain List (MDL)**: Checking if domains should have their IPs masked
- **First-party vs Third-party Context**: Determining the relationship between resources and top-level pages
- **IP Address Masking**: Masking IP addresses while preserving coarse geolocation

## Installation

No additional dependencies are required. The implementation uses only Python standard library modules:
- `ipaddress` for IP address handling
- `hashlib` for deterministic masking
- `urllib.parse` for URL parsing

## Usage

### Basic Example

```python
from ip_protection import IPProtection

# Initialize with a set of domains that should be masked in 3rd-party context
masked_domains = {
    'tracker.example.com',
    'ads.example.net',
    'analytics.test.com'
}

ip_protection = IPProtection(masked_domains)

# Process a request
resource_url = 'https://tracker.example.com/track.js'
top_level_url = 'https://mysite.org/page.html'
client_ip = '192.168.1.100'

result_ip, was_masked = ip_protection.process_request(
    resource_url, top_level_url, client_ip
)

if was_masked:
    print(f"IP masked: {client_ip} -> {result_ip}")
else:
    print(f"IP not masked: {result_ip}")
```

### Checking Individual Components

```python
# Check if domain is on MDL
is_on_list = ip_protection.is_on_mdl('tracker.example.com')

# Check if context is third-party
is_third_party = ip_protection.is_third_party_context(
    'tracker.example.com', 'mysite.org'
)

# Mask an IP address
masked_ip = ip_protection.mask_ip_address('192.168.1.100')

# Check if IP should be masked
should_mask = ip_protection.should_mask_ip(
    'tracker.example.com', 'mysite.org'
)
```

## Running Tests

Run the test suite using Python's unittest:

```bash
python3 -m unittest test_ip_protection.py -v
```

## Key Features

### 1. Masked Domain List (MDL)

The implementation maintains a list of domains that should have their IPs masked when accessed in a third-party context. Domain matching includes:
- Exact domain matches
- Subdomain matching (e.g., `sub.tracker.example.com` matches if `tracker.example.com` is on the list)
- Case-insensitive matching

### 2. First-party vs Third-party Detection

The implementation determines whether a resource is in a first-party or third-party context by:
- Comparing the resource domain with the top-level page domain
- Using registrable domain matching (e.g., `sub1.example.com` and `sub2.example.com` are considered first-party to each other)

### 3. IP Address Masking

The implementation masks IP addresses while preserving coarse geolocation:
- **IPv4**: Masks the last octet while preserving the /24 network prefix
- **IPv6**: Masks the last 64 bits while preserving the /64 network prefix
- Uses deterministic hashing to ensure the same input always produces the same masked output

### 4. Request Processing

The `process_request` method combines all the above features to:
1. Extract domains from URLs
2. Check if the resource domain is on the MDL
3. Determine if the context is third-party
4. Mask the IP address if both conditions are met
5. Return the appropriate IP address and masking status

## Design Decisions

This reference implementation makes several simplifications:

1. **Simplified Registrable Domain Extraction**: Uses a basic approach of taking the last two domain parts. A production implementation would use the Public Suffix List.

2. **Deterministic Masking**: Uses SHA-256 hashing for deterministic IP masking. A real implementation would use random proxy pool assignment.

3. **No Entity Mapping**: Does not implement the entity mapping that would determine common ownership of domains.

4. **No Geographic Assignment**: Does not implement actual geographic IP block assignment based on user location.

5. **No Proxy Infrastructure**: This is a logical implementation that demonstrates the decision-making process, not the actual proxying infrastructure.

## Alignment with Chrome IP Protection Proposal

This implementation demonstrates the following concepts from the proposal:

- ✅ List-based approach using the Masked Domain List
- ✅ First-party vs third-party context determination
- ✅ IP masking only for domains on the MDL in third-party context
- ✅ Preservation of coarse geolocation (network prefix)
- ✅ No masking for first-party contexts even if domain is on the MDL

## Limitations

This is a reference implementation for educational purposes. A production implementation would require:

- Integration with Chrome's networking stack
- Two-hop proxy infrastructure (ProxyA and ProxyB)
- Blind signature authentication scheme
- Token-based rate limiting
- Real Public Suffix List integration
- Entity mapping for common ownership
- Geographic IP block management
- Support for CONNECT and CONNECT-UDP (MASQUE) protocols

## License

This code is provided under the same Apache 2.0 license as the IP Protection proposal documentation.
