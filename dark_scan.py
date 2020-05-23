#!/usr/bin/python3
'''
TODO:
	- Add host discovery on local network.
DONE:
	- Add argument parsing.
'''

import argparse
from sys import argv
from random import randint
from scapy.all import *

timeout = 2

def parse_arguments():
	arguments = argparse.ArgumentParser()

	arguments.add_argument("-p", "--ports", type = int, help = "Target port/s")
	arguments.add_argument("-t", "--target", type = str, required = True, help = "Target address")
	arguments.add_argument("-d", "--discover", help = "Host discovery")

	return arguments.parse_args()


def host_discovery(target):
	live_hosts = []
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = target), timeout = timeout, verbose = 0)

	for snd, rcv in ans:
		live_hosts = rcv.pasrc
#		print(rcv.psrc)

	for host in live_hosts:
		print("Host %s is up\n" % (host))


def tcp_syn_scan(target, ports):
	open_ports = []
	scanned_ports = 0
	ip = IP(dst = target)
	
	print("Scaning %d ports\n" % (len(ports)))

	for port in ports:
		s_port = randint(49152, 65535)

		ans = sr1(ip/TCP(dport = port, sport = s_port), timeout = timeout, verbose = 0)

		print_percent(scanned_ports, len(ports))

		if ans.haslayer(TCP):
			if ans[TCP].flags == 20:
				pass
	#			print(i, "Closed")
			elif ans[TCP].flags == 18:
	#			print(i, "Open")
				open_ports.append(port)

		scanned_ports += 1

	return open_ports


def print_percent(counter, total_ports):
	print("\rCompleted: %d%%" % (counter * 100 / total_ports), end = '')


def print_results(open_ports):
	print('\r', ' ' * 20, '\r', end = '')

	for i in open_ports:
		print("Port %d open" % (i))

	print("\nFound %d open ports" % (len(open_ports)))


def main():
	args = parse_arguments()

	if args.ports is not None:
		ports = list(range(1, args.ports))

	target = args.target

	if args.discover is not None:
		host_discovery(target)

	open_ports = tcp_syn_scan(target, ports)

	print_results(open_ports)


if __name__ == "__main__":
	main()