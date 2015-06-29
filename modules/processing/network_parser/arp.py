__author__ = 'stark'


try:
    import dpkt
    IS_DPKT = True
except ImportError:
    IS_DPKT = False

# Verify if packet is ARP or RARP
class Arp:

    def __init__(self):
        pass

    def check(self, data):
        if isinstance(data, dpkt.arp.ARP):
            return True

    def dissect(self, arp):
        parp = {}

        parp["layer"] = 3
        if arp.op == dpkt.arp.ARP_OP_REVREPLY or arp.op == dpkt.arp.ARP_OP_REVREQUEST:
            parp["protocol_name"] = "RARP"
        else:
            parp["protocol_name"] = "ARP"

        return parp
