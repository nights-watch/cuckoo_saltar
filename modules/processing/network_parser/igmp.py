__author__ = 'targaryen'

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Igmp:

    def __init__(self):
        pass

    @staticmethod
    def checkv2(data):
        if isinstance(data, dpkt.igmp.IGMP):  # RFC 2236 - IGMP v2
            return True
        return False

    #def checkv3(self, data):
    #    if isinstance(data, dpkt.igmp6.IGMP6):  # RFC 3376 - IGMP v3
    #        return True
    #    return False

    @staticmethod
    def dissect(igmp):

        pigmp = {}

        if isinstance(igmp, dpkt.igmp.IGMP):  # RFC 792
            pigmp["protocol_name"] = "IGMP2"
            pigmp["layer"] = 3
            pigmp["type"] = igmp.type  # Type
            pigmp["max"] = igmp.maxresp  # Code
            pigmp["checksum"] = igmp.sum  # Checksum
            pigmp["group"] = igmp.group  # Group Address

        #elif isinstance(igmp, dpkt.igmp6.IGMP):  # RFC 4884
        #    pigmp["protocol_name"] = "ICMP6"
        #    pigmp["layer"] = 3
        #    pigmp["type"] = igmp.type  # Type
        #    pigmp["code"] = igmp.code  # Code
        #    pigmp["checksum"] = igmp.sum  # Checksum
        #    pigmp["identifier"] = igmp.id  # Identifier
        #    pigmp["sequence_number"] = igmp.seq  # Sequence Number

        return pigmp