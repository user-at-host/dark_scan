#!/usr/bin/env python3


import socks
import logging

from re import search
from sys import argv, stdout
from time import sleep
from random import randint
from argparse import ArgumentParser, Namespace
from subprocess import run, PIPE

from scapy.all import *

TIMEOUT = 2
BLOCK_SIZE = 100

FORMAT = '%(asctime)s %(levelname)s %(message)s'
logging.basicConfig(format=FORMAT, level=logging.DEBUG)

LOGGER = logging.getLogger()


def parse_arguments() -> Namespace:
	parser = ArgumentParser()

	parser.add_argument("-t", "--target", type=str, help="Target IP address")
	parser.add_argument("-p", "--ports", type=str, help="Port/s to scan. Supports the following formats: PORT or PORT_FROM-PORT_TO or PORT,PORT...")

	return parser.parse_args()


def parse_arguments_old():
	args = {}
	skip = 0

	if len(argv) == 1:
		print_help()

		exit()

	for i in range(1, len(argv)):
		if skip:
			skip = 0
			continue

		args["tor_scan"] = True

		if argv[i] == '-h':
			print_help()
			
			exit()
		elif argv[i] == '-t':
			args["target"] = argv[i + 1]

			skip = 1
		elif argv[i] == '-d':
			args["discover"] = True
		elif argv[i] == '-p':
			args["port"] = parse_ports(argv[i + 1])

			skip = 1
		elif argv[i] == '-r':
			args["resolve"] = True

			args["target"] = argv[i + 1]

			skip = 1
		elif argv[i] == '-nT':
			args["tor_scan"] = False
		else:
			print("Unknown option: %s" % (argv[i]))

			print_help()

			exit()


	return args


def check_ports(ports: str) -> bool:
	"""
	Checks the provided ports for correctness.
	:param ports: The given ports as a string
	:return: True if the given ports correct, else False
	"""

	LOGGER.debug(f"Checking port\s: {ports}")

	port_pattern = r"(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[0-5]?[0-9]{1,4})"

	if search(rf"^{port_pattern}$", ports):
		LOGGER.debug(f"The port {ports} matches the pattern {port_pattern}")

		return int(ports) != 0

	dash_pattern = rf"^{port_pattern}-{port_pattern}$"

	if search(dash_pattern, ports):
		LOGGER.debug(f"The ports {ports} matches the pattern {dash_pattern}")

		return True

	comma_pattern = rf"^({port_pattern}\,)+{port_pattern}$"

	if search(comma_pattern, ports):
		LOGGER.debug(f"The ports {ports} matches the pattern {comma_pattern}")

		return True

	LOGGER.debug(f"The port/s {ports} does not match any pattern")

	return False


def parse_ports(ports):
	if '-' in ports:
		ports = list(range(int(ports.split('-')[0]), int(ports.split('-')[1]) + 1))

		return ports
	else:
		return [int(ports)]


def print_help():
	print("Usage: dark_scan.py [OPTIONS]...\n")
	print("\t-t\t<IP address/URL>\tTarget")
	print("\t-p\t<Ports>\t\t\tPorts to scan")
	print("\t-r\t<URL>\t\t\tResolve host")
	print("\t-d\t\t\t\tHost discovery on local network")
	print("\t-nT\t\t\t\tDo not use Tor network (regular TCP SYN scan)")
	print("\n\tExamples:")
	print("\t\t./dark_scan.py -t 45.33.32.156 -p 1-1023")
	print("\t\t./dark_scan.py -t scanme.nmap.org -p 22")
	print("\t\t./dark_scan.py -r scanme.nmap.org")
	print("\t\t./dark_scan.py -d")
	print()


def host_discovery(ip_addresses, interfaces):
	for target, iface in zip(ip_addresses, interfaces):
		live_hosts = []
		live_mac = []

		ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = target),iface = iface, timeout = TIMEOUT, verbose = 0)

		print("Discovering hosts on %s network\n" % (target))

		for snd, rcv in ans:
			live_hosts.append(rcv.psrc)
			live_mac.append(rcv.src)

		for host, mac in zip(live_hosts, live_mac):
			print("IP: %s" % (host), end = '')

			if len(host) < 12:
				print('\t\t', end = '')
			else:
				print('\t', end = '')
			
			print("MAC: %s" % (mac))

		print()


def tcp_syn_scan(target, ports):
	open_ports = []
	scanned_ports = 0
	sport = randint(49152, 65535)

	if len(ports) > 1:
		port_chunks = generate_port_chunks(ports)
	else:
		port_chunks = [[0, 1]]

	for i in port_chunks:
		ip = IP(dst = target)
		tcp = TCP(sport = sport, dport = ports[i[0]:i[1]])
		ans, unans = sr(ip/tcp, timeout = TIMEOUT, verbose = 0)

		for snd, rcv in ans:
			scanned_ports += 1
			if rcv.haslayer(TCP):
				tcp_layer = rcv.getlayer(TCP)

				if tcp_layer.flags == 20:
						pass
				elif tcp_layer.flags == 18:
					open_ports.append(tcp_layer.sport)

	return open_ports, scanned_ports


def generate_port_chunks(ports):
	port_chunks = []

	for i in range(0, len(ports), 200):
		port_chunks.append([i, i + 200])

	return port_chunks


def tor_scan(target, ports):
	open_ports = []
	scanned_ports = 0

	socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050, True)

	for port in ports:
		try:
			s = socks.socksocket()

			scanned_ports += 1

			s.connect((target, port))
			s.close()

			open_ports.append(port)
		except socks.GeneralProxyError:
			pass

	return open_ports, scanned_ports


def print_results(open_ports, scanned_ports, protocol):
	print('\r', ' ' * 20, '\r', end = '')

	for i in open_ports:
		print("Port %d open %s" % (i, protocol))

	if scanned_ports == 1:
		print("\nScanned 1 port")
	else:
		print("\nScanned %d ports" % (scanned_ports))

	if len(open_ports) == 1:
		print("Found 1 open port")
	else:
		print("Found %d open ports" % (len(open_ports)))


def check_ipv4_address(address: str) -> bool:
	"""
	The function checks if the given IPv4 address is valid.
	:param address: The IPv4 address to check.
	:return: True if address is valid, else False.
	"""

	pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

	LOGGER.debug(f"Checking the IPv4 address {address}")

	if search(pattern, address):
		LOGGER.debug(f"The address {address} matches the pattern {pattern}")

		return True

	LOGGER.debug(f"The address {address} does not match the pattern {pattern}")

	return False


def resolve_address(url):
	print("Resolving: %s" % (url))

	pattern = "^http[s]?://"

	if search(pattern, url):
		url = url.split('//')[1]

	pattern = "\\.*/"

	if search(pattern, url):
		url = url.split('/')[0]
	
	return socket.gethostbyname(url)


def check_tor_service():
	process = run(args = ['service', 'tor', 'status'], stdout = PIPE)

	if process.returncode == 0:
		return True
	elif process.returncode == 3:
		return False
	else:
		print("Error: %d" % (process.returncode))

		exit(1)


def start_tor_service():
	process = run(args = ['service', 'tor', 'start'], stdout = PIPE)

	return process.returncode


def get_local_ip_addresses():
	output = run(['ip', 'a'], capture_output = True)
	pattern = "^127\\."
	pattern_2 = "[0-9]:"

	ip_addresses = []
	interfaces = []
	
	for line in output.stdout.decode().split('\n'):
		try:
			if line.split(' ')[4] == 'inet':
				if not search(pattern, line.split(' ')[5]):
					ip_addresses.append(line.split(' ')[5])
		except IndexError:
			pass

		try:
			if search(pattern_2, line.split(' ')[0]) and line.split(' ')[1][:-1] != 'lo':
				interfaces.append(line.split(' ')[1][:-1])
		except IndexError:
			pass

	return ip_addresses, interfaces


def main():
	args = parse_arguments()

	if check_ipv4_address(args.target):
		target = args.target
	else:
		print(f"Error: The address {args.target} is not a valid IPv4 address", file=stdout)

		exit(1)

	if check_ports(args.ports):
		ports = args.ports
	else:
		print(f"Error: The port/s {args.ports} not valid", file=stdout)

		exit(1)

	'''
	if "resolve" in args:
		address = resolve_address(args["target"])
		print("Address: %s" % (address))

		exit(0)

	if args["tor_scan"] and not check_tor_service():
		ans = input("Tor service is not running, enable it [Y, n]? ")

		if ans.lower() == 'y' or ans == '':
			ret_code = start_tor_service()
			if ret_code == 0:
				sleep(1)

				print("INFO: Tor service started succesfully\n")
			else:
				print("Error: Failed to start Tor service.\n\
					Process exited with return code: %d" % (ret_code))

				exit(1)

	if "discover" in args:
		ip_addresses, interfaces = get_local_ip_addresses()
		host_discovery(ip_addresses, interfaces)
	else:
		ports = args["port"]
		target = check_address(args["target"]) 

		print("Scaning target: %s\n" % (target))

		if args["tor_scan"]:
			open_ports, scanned_ports = tor_scan(target, ports)
		else:
			open_ports, scanned_ports = tcp_syn_scan(target, ports)

		print_results(open_ports, scanned_ports, "TCP")
	'''


if __name__ == "__main__":
	main()
