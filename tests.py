#!/usr/bin/env python3

from unittest import main, TestCase
from dark_scan import check_ipv4_address
from dark_scan import check_ports

class TestDarkScan(TestCase):
    def test_ports(self):
        self.assertTrue(check_ports("11111"))
        self.assertTrue(check_ports("1-11"))
        self.assertTrue(check_ports("1,2,3"))

        self.assertFalse(check_ports("0"))
        self.assertFalse(check_ports("99999"))
        self.assertFalse(check_ports("1,1.1"))
        self.assertFalse(check_ports("1-9-19"))

    def test_ipv4_addresses(self):
        self.assertTrue(check_ipv4_address("1.1.1.1"))
        self.assertTrue(check_ipv4_address("42.46.51.129"))
        self.assertTrue(check_ipv4_address("231.255.7.85"))
        self.assertTrue(check_ipv4_address("254.73.163.76"))
        self.assertTrue(check_ipv4_address("115.124.241.108"))
        self.assertTrue(check_ipv4_address("239.142.108.140"))
        self.assertTrue(check_ipv4_address("255.11.1.1"))

        self.assertFalse(check_ipv4_address("1.1.1.1.1"))
        self.assertFalse(check_ipv4_address("1.1.1"))
        self.assertFalse(check_ipv4_address("1.1.1."))
        self.assertFalse(check_ipv4_address("1.1.1.1111"))
        self.assertFalse(check_ipv4_address("1.1.1111.1"))
        self.assertFalse(check_ipv4_address("1.1111.1.1"))
        self.assertFalse(check_ipv4_address("1111.1.1.1"))
        self.assertFalse(check_ipv4_address("321.111.1.1"))
        self.assertFalse(check_ipv4_address("1.300.1.1"))
        self.assertFalse(check_ipv4_address("256.11.1.1"))


if __name__ == '__main__':
    main()
