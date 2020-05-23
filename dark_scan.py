#!/usr/bin/python3
'''
TODO:
	- Translate URLs to IP address.
DONE:
	- Add host discovery on local network.
	- Add argument parsing.
'''

from sys import argv
from random import randint
from scapy.all import *

TIMEOUT = 2

def parse_arguments():
	args = {}
	skip = 0

	if len(argv) == 1:
		print_help()

		exit()

	for i in range(1, len(argv)):
		if skip:
			skip = 0
			continue

		if argv[i] == '-h':
			print_help()
			
			exit()
		elif argv[i] == '-d':
			args["h_discover"] = True

			args["target"] = argv[i + 1]

			skip = 1
		elif argv[i] == '-t':
			args["target"] = argv[i + 1]

			skip = 1
		elif argv[i] == '-p':
			args["port"] = int(argv[i + 1])

			skip = 1
		else:
			print("Unknown option: %s" % (argv[i]))

			print_help()

			exit()


	return args


def print_help():
	print("Usage: dark_scan [OPTIONS]...\n")
	print("\t-d\t<IP address range>\tHost discovery")
	print("\t-t\t<IP address>\t\tHost to scan")
	print("\t-p\t<Ports>\t\t\tPorts to scan")


def host_discovery(target):
	live_hosts = []
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = target), timeout = TIMEOUT, verbose = 0)

	for snd, rcv in ans:
		live_hosts.append(rcv.psrc)

	for host in live_hosts:
		print("Host: %s is up" % (host))

	print()


def tcp_syn_scan(target, ports):
	open_ports = []
	scanned_ports = 0
	ip = IP(dst = target)
	
	print("Scaning %d ports\n" % (len(ports)))

	for port in ports:
		s_port = randint(49152, 65535)

		ans = sr1(ip/TCP(dport = port, sport = s_port), timeout = TIMEOUT, verbose = 0)

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


def print_results(open_ports, protocol):
	print('\r', ' ' * 20, '\r', end = '')

	for i in open_ports:
		print("Port %d open %s" % (i, protocol))

	print("\nFound %d open ports" % (len(open_ports)))


def main():
	args = parse_arguments()

	if "h_discover" in args:
		host_discovery(args["target"])
	else:
		target = args["target"]
		ports = list(range(1, args["port"]))

		print_results(tcp_syn_scan(target, ports), "TCP")


if __name__ == "__main__":
	main()