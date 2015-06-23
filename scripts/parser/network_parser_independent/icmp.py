__author__ = 'targaryen'

from parser_utils import convert_to_printable

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Icmp:
    def __init__(self):
        pass

    @staticmethod
    def check(icmp_data):
        """Checks for ICMP traffic.
        @param icmp_data: ICMP data flow.
        """
        try:
            return isinstance(icmp_data, dpkt.icmp.ICMP)
        except:
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

        picmp["protocol_name"] = "ICMP"
        picmp["layer"] = 3
        # picmp["src"] = pip["src"]
        # picmp["dst"] = pip["dst"]
        picmp["type"] = data.type  # Type
        picmp["code"] = data.code  # Code
        picmp["checksum"] = data.sum  # Checksum

        # Extract data from dpkg.icmp.ICMP.
        try:
            picmp["data"] = convert_to_printable(data.data.data)
        except:
            picmp["data"] = ""

        return picmp



