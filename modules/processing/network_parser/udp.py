__author__ = 'targaryen'

from dns import Dns as dns

try:
    import dpkt
    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Udp:

    def __init__(self):
        pass

    @staticmethod
    def check(data):
        if data == dpkt.ip.IP_PROTO_UDP:
            return True
        return False

    @staticmethod
    def dissect(udp):
        pudp={}
        pudp["layer"] = 4
        pudp["protocol_name"] = "UDP"
        pudp["sport"] = udp.sport  # Source port
        pudp["dport"] = udp.dport  # Destination port
        pudp["ulen"] = udp.ulen  # Length
        pudp["usum"] = udp.sum  # Checksum

        if dns.check(udp):
            pudp["payload"] = dns.dissect(udp.data)
        else:
            pudp["payload"] = "unknown protocol on layer " + str(pudp["layer"]+1)

        return pudp
