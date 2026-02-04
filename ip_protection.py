"""
IP Protection Module

A reference implementation demonstrating IP Protection concepts as described
in the Chrome IP Protection proposal. This module provides functionality for:
- Checking if a domain is on the Masked Domain List (MDL)
- Determining first-party vs third-party context
- Masking IP addresses for privacy protection
"""

import ipaddress
import hashlib
from typing import Optional, Set
from urllib.parse import urlparse


class IPProtection:
    """
    IP Protection implementation that masks IP addresses for domains
    on the Masked Domain List when accessed in third-party context.
    """
    
    def __init__(self, masked_domains: Optional[Set[str]] = None):
        """
        Initialize IP Protection with a set of masked domains.
        
        Args:
            masked_domains: Set of domain names that should have IPs masked
                          when accessed in third-party context
        """
        self.masked_domains = masked_domains or set()
    
    def is_on_mdl(self, domain: str) -> bool:
        """
        Check if a domain is on the Masked Domain List.
        
        Args:
            domain: Domain name to check
            
        Returns:
            True if domain is on the MDL, False otherwise
        """
        # Normalize domain
        domain = domain.lower().strip()
        
        # Check exact match and parent domains
        if domain in self.masked_domains:
            return True
        
        # Check if any parent domain is on the list
        parts = domain.split('.')
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self.masked_domains:
                return True
        
        return False
    
    def is_third_party_context(self, resource_domain: str, top_level_domain: str) -> bool:
        """
        Determine if a resource is in third-party context.
        
        Args:
            resource_domain: Domain of the resource being loaded
            top_level_domain: Domain of the top-level page
            
        Returns:
            True if resource is in third-party context, False otherwise
        """
        # Normalize domains
        resource_domain = resource_domain.lower().strip()
        top_level_domain = top_level_domain.lower().strip()
        
        # Same domain is first-party
        if resource_domain == top_level_domain:
            return False
        
        # Get registrable domains (simplified)
        resource_base = self._get_registrable_domain(resource_domain)
        top_level_base = self._get_registrable_domain(top_level_domain)
        
        # Same registrable domain is first-party
        return resource_base != top_level_base
    
    def _get_registrable_domain(self, domain: str) -> str:
        """
        Extract the registrable domain (simplified implementation).
        
        Args:
            domain: Full domain name
            
        Returns:
            Registrable domain (e.g., 'example.com' from 'sub.example.com')
        """
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain
    
    def mask_ip_address(self, ip_address: str, geolocation_hint: Optional[str] = None) -> str:
        """
        Mask an IP address to preserve privacy while maintaining coarse geolocation.
        
        Args:
            ip_address: Original IP address to mask
            geolocation_hint: Optional country/region hint for the masked IP
            
        Returns:
            Masked IP address
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            # For IPv4, mask the last octet
            if isinstance(ip_obj, ipaddress.IPv4Address):
                # Create a masked version by keeping network prefix
                network = ipaddress.IPv4Network(f"{ip_address}/24", strict=False)
                # Return a pseudo-random IP from the same /24 network
                hash_val = int(hashlib.sha256(ip_address.encode()).hexdigest()[:8], 16)
                masked_host = (hash_val % 254) + 1  # 1-254 range
                return str(network.network_address + masked_host)
            
            # For IPv6, mask the last 64 bits
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                # Keep the /64 network prefix
                network = ipaddress.IPv6Network(f"{ip_address}/64", strict=False)
                # Generate a pseudo-random host portion
                hash_val = int(hashlib.sha256(ip_address.encode()).hexdigest()[:16], 16)
                masked_host = hash_val % (2**64)
                return str(network.network_address + masked_host)
            
        except ValueError:
            # Invalid IP address
            return ip_address
        
        return ip_address
    
    def should_mask_ip(self, resource_domain: str, top_level_domain: str) -> bool:
        """
        Determine if IP should be masked for a given resource.
        
        Args:
            resource_domain: Domain of the resource being accessed
            top_level_domain: Domain of the top-level page
            
        Returns:
            True if IP should be masked, False otherwise
        """
        # IP is masked only if:
        # 1. Domain is on the MDL
        # 2. Domain is accessed in third-party context
        return (self.is_on_mdl(resource_domain) and 
                self.is_third_party_context(resource_domain, top_level_domain))
    
    def process_request(self, resource_url: str, top_level_url: str, 
                       client_ip: str) -> tuple[str, bool]:
        """
        Process a request and determine the IP to use.
        
        Args:
            resource_url: URL of the resource being requested
            top_level_url: URL of the top-level page
            client_ip: Original client IP address
            
        Returns:
            Tuple of (ip_address_to_use, was_masked)
        """
        # Extract domains from URLs
        resource_domain = urlparse(resource_url).netloc
        top_level_domain = urlparse(top_level_url).netloc
        
        # Check if IP should be masked
        if self.should_mask_ip(resource_domain, top_level_domain):
            masked_ip = self.mask_ip_address(client_ip)
            return (masked_ip, True)
        
        return (client_ip, False)
