__author__ = 'stark'

import socket


try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False


class Arp:
    '''
    >>> a = Arp()
    '''
    def __init__(self):
        pass

    def check(self, data):
        if isinstance(data, dpkt.arp.ARP):
            return True

    def dissect(self, arp):
        '''
        >>> a.dissect(bla)
        ashuahsuahs
        :param arp:
        :return:
        '''
        '''
        :param arp:
        :return:
        '''
        parp = {}

        parp["layer"] = 3
        if arp.op == dpkt.arp.ARP_OP_REVREPLY or arp.op == dpkt.arp.ARP_OP_REVREQUEST:
            parp["protocol_name"] = "RARP"
        else:
            parp["protocol_name"] = "ARP"
        parp["hrd"] = arp.hrd  # Hardware Type
        parp["protype"] = arp.pro  # Protocol Type
        parp["hln"] = arp.hln  # Hardware Address Length
        parp["pln"] = arp.pln  # Protocol Address Length
        parp["op"] = arp.op  # Opcode
        parp["sha"] = arp.sha  # Source Hardware Address - MAC ADDRESS format
        parp["spa"] = socket.inet_ntoa(arp.spa)  # Source Protocol Address - IP Address format
        parp["dha"] = arp.tha  # Destination hardware address - MAC ADDRESS format
        parp["dpa"] = socket.inet_ntoa(arp.tpa)  # Destination protocol address - MAC ADDRESS format

        return parp
