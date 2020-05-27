# dark_scan
WORK IN PROGRESS

A port scanner that uses the Tor network to scan target hosts.

Usage: dark_scan.py [OPTIONS]...

        -d      <IP address/CIDR>       Host discovery on local network
        -t      <IP address/URL>        Target
        -p      <Ports>                 Ports to scan
        -r      <URL>                   Resolve host
        -nt                             Do not use Tor network (regular TCP SYN scan)

        Examples:
                ./dark_scan.py -t 45.33.32.156 -p 1-1023
                ./dark_scan.py -r scanme.nmap.org
                ./dark_scan.py -d 192.168.1.1/24

