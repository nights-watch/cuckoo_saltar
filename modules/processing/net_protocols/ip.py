__author__ = 'targaryen'

import struct
import socket
from lib.cuckoo.common.utils import convert_to_printable
import tcp
import udp
import icmp

try:
    import dpkt
    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Ip:

    def __init__(self):
        self.hosts = []
        # List containing all non-private IP addresses.
        self.unique_hosts = []
        self.udp = udp.Udp()
        self.tcp = tcp.Tcp(tcp)
        self.icmp = icmp.Icmp()

    def _is_private_ip(self, ip):
        """Check if the IP belongs to private network blocks.
        @param ip: IP address to verify.
        @return: boolean representing whether the IP belongs or not to
                 a private network block.
        """
        networks = [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "240.0.0.0/4",
            "255.255.255.255/32",
            "224.0.0.0/4"
        ]

        for network in networks:
            try:
                ipaddr = struct.unpack(">I", socket.inet_aton(ip))[0]

                netaddr, bits = network.split("/")

                network_low = struct.unpack(">I", socket.inet_aton(netaddr))[0]
                network_high = network_low | (1 << (32 - int(bits))) - 1

                if ipaddr <= network_high and ipaddr >= network_low:
                    return True
            except:
                continue

        return False

    def add_hosts(self, connection):
        """Add IPs to unique list.
        @param connection: connection data
        """
        try:
            if connection["src"] not in self.hosts:
                ip = convert_to_printable(connection["src"])

                # We consider the IP only if it hasn't been seen before.
                if ip not in self.hosts:
                    # If the IP is not a local one, this might be a leftover
                    # packet as described in issue #249.
                    if self._is_private_ip(ip):
                        self.hosts.append(ip)

            if connection["dst"] not in self.hosts:
                ip = convert_to_printable(connection["dst"])

                if ip not in self.hosts:
                    self.hosts.append(ip)

                    # We add external IPs to the list, only the first time
                    # we see them and if they're the destination of the
                    # first packet they appear in.
                    if not self._is_private_ip(ip):
                        self.unique_hosts.append(ip)
        except:
            pass




