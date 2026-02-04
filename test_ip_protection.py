"""
Tests for IP Protection Module
"""

import unittest
from ip_protection import IPProtection


class TestIPProtection(unittest.TestCase):
    """Test cases for IPProtection class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create instance with sample masked domains
        self.masked_domains = {
            'tracker.example.com',
            'ads.example.net',
            'analytics.test.com'
        }
        self.ip_protection = IPProtection(self.masked_domains)
    
    def test_is_on_mdl_exact_match(self):
        """Test exact domain match on MDL"""
        self.assertTrue(self.ip_protection.is_on_mdl('tracker.example.com'))
        self.assertFalse(self.ip_protection.is_on_mdl('other.example.com'))
    
    def test_is_on_mdl_subdomain(self):
        """Test subdomain checking on MDL"""
        # Subdomain of a listed domain should match
        self.assertTrue(self.ip_protection.is_on_mdl('sub.tracker.example.com'))
        self.assertFalse(self.ip_protection.is_on_mdl('sub.other.example.com'))
    
    def test_is_on_mdl_case_insensitive(self):
        """Test case-insensitive domain matching"""
        self.assertTrue(self.ip_protection.is_on_mdl('TRACKER.EXAMPLE.COM'))
        self.assertTrue(self.ip_protection.is_on_mdl('Tracker.Example.Com'))
    
    def test_is_third_party_context_same_domain(self):
        """Test first-party context (same domain)"""
        self.assertFalse(
            self.ip_protection.is_third_party_context(
                'example.com', 'example.com'
            )
        )
    
    def test_is_third_party_context_same_registrable_domain(self):
        """Test first-party context (same registrable domain)"""
        self.assertFalse(
            self.ip_protection.is_third_party_context(
                'sub1.example.com', 'sub2.example.com'
            )
        )
    
    def test_is_third_party_context_different_domains(self):
        """Test third-party context (different domains)"""
        self.assertTrue(
            self.ip_protection.is_third_party_context(
                'tracker.example.com', 'mysite.org'
            )
        )
    
    def test_mask_ip_address_ipv4(self):
        """Test IPv4 address masking"""
        original_ip = '192.168.1.100'
        masked_ip = self.ip_protection.mask_ip_address(original_ip)
        
        # Masked IP should be different
        self.assertNotEqual(original_ip, masked_ip)
        
        # But should be in same /24 network
        self.assertTrue(masked_ip.startswith('192.168.1.'))
        
        # Should be deterministic (same input = same output)
        masked_ip2 = self.ip_protection.mask_ip_address(original_ip)
        self.assertEqual(masked_ip, masked_ip2)
    
    def test_mask_ip_address_ipv6(self):
        """Test IPv6 address masking"""
        original_ip = '2001:db8::1'
        masked_ip = self.ip_protection.mask_ip_address(original_ip)
        
        # Masked IP should be different
        self.assertNotEqual(original_ip, masked_ip)
        
        # Should preserve /64 network prefix
        self.assertTrue(masked_ip.startswith('2001:db8:'))
        
        # Should be deterministic
        masked_ip2 = self.ip_protection.mask_ip_address(original_ip)
        self.assertEqual(masked_ip, masked_ip2)
    
    def test_mask_ip_address_invalid(self):
        """Test handling of invalid IP address"""
        invalid_ip = 'not-an-ip'
        result = self.ip_protection.mask_ip_address(invalid_ip)
        # Should return original if invalid
        self.assertEqual(result, invalid_ip)
    
    def test_should_mask_ip_third_party_on_mdl(self):
        """Test masking required for third-party MDL domain"""
        self.assertTrue(
            self.ip_protection.should_mask_ip(
                'tracker.example.com', 'mysite.org'
            )
        )
    
    def test_should_mask_ip_first_party_on_mdl(self):
        """Test no masking for first-party even if on MDL"""
        self.assertFalse(
            self.ip_protection.should_mask_ip(
                'tracker.example.com', 'tracker.example.com'
            )
        )
    
    def test_should_mask_ip_third_party_not_on_mdl(self):
        """Test no masking for third-party not on MDL"""
        self.assertFalse(
            self.ip_protection.should_mask_ip(
                'other.example.com', 'mysite.org'
            )
        )
    
    def test_process_request_masking_required(self):
        """Test full request processing with masking"""
        resource_url = 'https://tracker.example.com/track.js'
        top_level_url = 'https://mysite.org/page.html'
        client_ip = '192.168.1.100'
        
        result_ip, was_masked = self.ip_protection.process_request(
            resource_url, top_level_url, client_ip
        )
        
        self.assertTrue(was_masked)
        self.assertNotEqual(result_ip, client_ip)
        self.assertTrue(result_ip.startswith('192.168.1.'))
    
    def test_process_request_no_masking_required(self):
        """Test full request processing without masking"""
        resource_url = 'https://mysite.org/script.js'
        top_level_url = 'https://mysite.org/page.html'
        client_ip = '192.168.1.100'
        
        result_ip, was_masked = self.ip_protection.process_request(
            resource_url, top_level_url, client_ip
        )
        
        self.assertFalse(was_masked)
        self.assertEqual(result_ip, client_ip)
    
    def test_empty_masked_domains(self):
        """Test with empty masked domain list"""
        ip_protection = IPProtection(set())
        
        self.assertFalse(ip_protection.is_on_mdl('any.domain.com'))
        self.assertFalse(
            ip_protection.should_mask_ip('any.domain.com', 'other.com')
        )


if __name__ == '__main__':
    unittest.main()
