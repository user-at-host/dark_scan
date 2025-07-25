#!/usr/bin/env python3

from unittest import main, TestCase
from dark_scan import check_ipv4_address
from dark_scan import check_ports

class TestDarkScan(TestCase):
    def test_ports(self):
        self.assertTrue(check_ports("11111"))
        self.assertTrue(check_ports("1-11"))
        self.assertTrue(check_ports("1,2,3"))

        self.assertFalse(check_ports("99999"))
        self.assertFalse(check_ports("1,1.1"))
        self.assertFalse(check_ports("1-9-19"))

    def test_ipv4_addresses(self):
        self.assertTrue(check_ipv4_address("1.1.1.1"))


if __name__ == '__main__':
    main()
