#!/usr/bin/env python3
"""
Example usage of the IP Protection module

This script demonstrates various scenarios of IP protection in action,
showing when IPs are masked and when they are not.
"""

from ip_protection import IPProtection


def print_scenario(title, description=""):
    """Print a formatted scenario header"""
    print(f"\n{'='*70}")
    print(f"Scenario: {title}")
    if description:
        print(f"Description: {description}")
    print('='*70)


def main():
    """Demonstrate IP Protection functionality with various scenarios"""
    
    # Initialize IP Protection with sample masked domains
    # These would typically come from the official Masked Domain List (MDL)
    masked_domains = {
        'tracker.example.com',
        'ads.advertising.net',
        'analytics.measurement.com',
        'pixel.tracking.io'
    }
    
    ip_protection = IPProtection(masked_domains)
    
    print("\n" + "="*70)
    print("IP Protection Reference Implementation - Examples")
    print("="*70)
    print("\nMasked Domain List (MDL) contains:")
    for domain in sorted(masked_domains):
        print(f"  - {domain}")
    
    # Scenario 1: Third-party tracker on MDL
    print_scenario(
        "Third-party Tracker on MDL",
        "User visits mysite.org which embeds tracker.example.com"
    )
    
    resource_url = "https://tracker.example.com/track.js"
    top_level_url = "https://mysite.org/index.html"
    client_ip = "203.0.113.45"
    
    result_ip, was_masked = ip_protection.process_request(
        resource_url, top_level_url, client_ip
    )
    
    print(f"Resource: {resource_url}")
    print(f"Top-level page: {top_level_url}")
    print(f"Original IP: {client_ip}")
    print(f"Result IP: {result_ip}")
    print(f"Was masked: {was_masked}")
    print(f"✓ IP was masked because domain is on MDL and context is 3rd-party")
    
    # Scenario 2: First-party access to domain on MDL
    print_scenario(
        "First-party Access to Domain on MDL",
        "User directly visits tracker.example.com"
    )
    
    resource_url = "https://tracker.example.com/index.html"
    top_level_url = "https://tracker.example.com/index.html"
    client_ip = "203.0.113.45"
    
    result_ip, was_masked = ip_protection.process_request(
        resource_url, top_level_url, client_ip
    )
    
    print(f"Resource: {resource_url}")
    print(f"Top-level page: {top_level_url}")
    print(f"Original IP: {client_ip}")
    print(f"Result IP: {result_ip}")
    print(f"Was masked: {was_masked}")
    print(f"✓ IP was NOT masked because context is 1st-party")
    
    # Scenario 3: Third-party domain NOT on MDL
    print_scenario(
        "Third-party Domain NOT on MDL",
        "User visits mysite.org which embeds cdn.cloudprovider.com"
    )
    
    resource_url = "https://cdn.cloudprovider.com/library.js"
    top_level_url = "https://mysite.org/index.html"
    client_ip = "203.0.113.45"
    
    result_ip, was_masked = ip_protection.process_request(
        resource_url, top_level_url, client_ip
    )
    
    print(f"Resource: {resource_url}")
    print(f"Top-level page: {top_level_url}")
    print(f"Original IP: {client_ip}")
    print(f"Result IP: {result_ip}")
    print(f"Was masked: {was_masked}")
    print(f"✓ IP was NOT masked because domain is not on MDL")
    
    # Scenario 4: Subdomain matching
    print_scenario(
        "Subdomain of MDL Domain",
        "Subdomain of a tracked domain is also protected"
    )
    
    resource_url = "https://api.tracker.example.com/v1/track"
    top_level_url = "https://mysite.org/index.html"
    client_ip = "203.0.113.45"
    
    result_ip, was_masked = ip_protection.process_request(
        resource_url, top_level_url, client_ip
    )
    
    print(f"Resource: {resource_url}")
    print(f"Top-level page: {top_level_url}")
    print(f"Original IP: {client_ip}")
    print(f"Result IP: {result_ip}")
    print(f"Was masked: {was_masked}")
    print(f"✓ IP was masked because subdomains of MDL entries are also masked")
    
    # Scenario 5: Same registrable domain (different subdomains)
    print_scenario(
        "Same Registrable Domain",
        "Resources from different subdomains of the same site"
    )
    
    resource_url = "https://cdn.mysite.org/app.js"
    top_level_url = "https://www.mysite.org/index.html"
    client_ip = "203.0.113.45"
    
    result_ip, was_masked = ip_protection.process_request(
        resource_url, top_level_url, client_ip
    )
    
    print(f"Resource: {resource_url}")
    print(f"Top-level page: {top_level_url}")
    print(f"Original IP: {client_ip}")
    print(f"Result IP: {result_ip}")
    print(f"Was masked: {was_masked}")
    print(f"✓ IP was NOT masked because both domains share the same registrable domain")
    
    # Scenario 6: IPv6 address masking
    print_scenario(
        "IPv6 Address Masking",
        "Demonstrating IPv6 support"
    )
    
    resource_url = "https://tracker.example.com/track.js"
    top_level_url = "https://mysite.org/index.html"
    client_ip = "2001:db8:85a3::8a2e:370:7334"
    
    result_ip, was_masked = ip_protection.process_request(
        resource_url, top_level_url, client_ip
    )
    
    print(f"Resource: {resource_url}")
    print(f"Top-level page: {top_level_url}")
    print(f"Original IPv6: {client_ip}")
    print(f"Result IPv6: {result_ip}")
    print(f"Was masked: {was_masked}")
    print(f"✓ IPv6 address masked with /64 network prefix preserved")
    
    # Summary
    print("\n" + "="*70)
    print("Summary")
    print("="*70)
    print("""
IP Protection masks IP addresses when BOTH conditions are met:
  1. The resource domain is on the Masked Domain List (MDL)
  2. The resource is accessed in a third-party context

This provides privacy protection against cross-site tracking while:
  - Preserving functionality for first-party contexts
  - Maintaining coarse geolocation information
  - Not affecting domains not on the MDL
    """)


if __name__ == '__main__':
    main()
