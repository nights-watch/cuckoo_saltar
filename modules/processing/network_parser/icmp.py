__author__ = 'targaryen'

from lib.cuckoo.common.utils import convert_to_printable

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Icmp:
    def __init__(self):
        pass

    def checkv4(self, data):
        if isinstance(data, dpkt.icmp.ICMP):  # RFC 792
            return True
        return False

    def checkv6(self, data):
        if isinstance(data, dpkt.icmp6.ICMP6):  # RFC 4884
            return True
        return False

    #TODO Remove src dst
    @staticmethod
    def dissect(data):

        """Runs all ICMP dissectors.
        RFC 792
        @param conn: connection.
        @param data: payload data of protocol IP.
        """

        picmp = {}

        if isinstance(data, dpkt.icmp.ICMP):  # RFC 792
            picmp["protocol_name"] = "ICMP"
            picmp["layer"] = 3
            picmp["type"] = data.type  # Type
            picmp["code"] = data.code  # Code
            picmp["checksum"] = data.sum  # Checksum

            # Extract data from dpkg.icmp.ICMP.
            try:
                picmp["data"] = convert_to_printable(data.data.data)
            except:
                picmp["data"] = ""

        elif isinstance(data, dpkt.icmp6.ICMP6):  # RFC 4884
            picmp["protocol_name"] = "ICMP6"
            picmp["layer"] = 3
            picmp["type"] = data.type  # Type
            picmp["code"] = data.code  # Code
            picmp["checksum"] = data.sum  # Checksum
            picmp["identifier"] = data.id  # Identifier
            picmp["sequence_number"] = data.seq  # Sequence Number

            # Extract data from dpkg.icmp.ICMP.
            try:
                picmp["data"] = convert_to_printable(data.data.data)
            except:
                picmp["data"] = ""

        return picmp



