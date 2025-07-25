#!/usr/bin/env python3

from unittest import main, TestCase
from dark_scan import check_ipv4_address
from dark_scan import check_ports

class TestDarkScan(TestCase):
    def test_ports(self):
        self.assertTrue(check_ports("11111"))
        self.assertTrue(check_ports("1-11"))
        self.assertTrue(check_ports("1,2,3"))

if __name__ == '__main__':
    main()
