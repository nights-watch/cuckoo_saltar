__author__ = 'targaryen'

from lib.cuckoo.common.utils import convert_to_printable
from lib.cuckoo.common.config import Config


try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Icmp:


    #TODO create singleton
    def __init__(self):
        # List containing all ICMP requests.
        self.icmp_requests = []

    def _check_icmp(self, icmp_data):
        """Checks for ICMP traffic.
        @param icmp_data: ICMP data flow.
        """
        try:
            return isinstance(icmp_data, dpkt.icmp.ICMP) and \
                   len(icmp_data.data) > 0
        except:
            return False

    def icmp_dissect(self, conn, data):
        """Runs all ICMP dissectors.
        RFC 792
        @param conn: connection.
        @param data: payload data of protocol IP.
        """

        if self._check_icmp(data):
            # If ICMP packets are coming from the host, it probably isn't
            # relevant traffic, hence we can skip from reporting it.
            if conn["src"] == Config().resultserver.ip:
                return

            entry = {}
            icmp = {}
            entry["src"] = conn["src"]
            entry["dst"] = conn["dst"]
            entry["type"] = data.type

            # Populate ICMP package
            icmp["type"] = data.type  # Type
            icmp["code"] = data.code  # Code
            icmp["checksum"] = data.sum  # Checksum


            # Extract data from dpkg.icmp.ICMP.
            try:
                entry["data"] = convert_to_printable(data.data.data)
            except:
                entry["data"] = ""

            icmp["data"] = entry["data"]  # Data

            self.icmp_requests.append(entry)

            return icmp




