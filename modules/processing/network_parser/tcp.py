__author__ = 'targaryen'

from http import Http as http
from smtp import Smtp as smtp
from irc import Irc as irc
from dns import Dns as dns
from ssl import Ssl as ssl

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Tcp:

    def __init__(self, pcap):
        pass

    @staticmethod
    def check(data):
        if data == dpkt.ip.IP_PROTO_TCP:
            return True
        return False

    @staticmethod
    def tcp_flags(flags):
        """Identify flags TCP of a packet."""
        # Initializing all flags with '0'
        all_flags = {"NS": 0, "CWR": 0, "ECE": 0, "URG": 0, "ACK": 0, "PSH": 0, "RST": 0, "SYN": 0, "FIN": 0}
        if (flags & 0b000000000001) == dpkt.tcp.TH_FIN:
            all_flags["FIN"] = 1
        if (flags & 0b000000000010) == dpkt.tcp.TH_SYN:
            all_flags["SYN"] = 1
        if (flags & 0b000000000100) == dpkt.tcp.TH_RST:
            all_flags["RST"] = 1
        if (flags & 0b000000001000) == dpkt.tcp.TH_PUSH:
            all_flags["PSH"] = 1
        if (flags & 0b000000010000) == dpkt.tcp.TH_ACK:
            all_flags["ACK"] = 1
        if (flags & 0b000000100000) == dpkt.tcp.TH_URG:
            all_flags["URG"] = 1
        if (flags & 0b000001000000) == dpkt.tcp.TH_ECE:
            all_flags["ECE"] = 1
        if (flags & 0b000010000000) == dpkt.tcp.TH_CWR:
            all_flags["CWR"] = 1
        if (flags & 0b000100000000) == 0x100:
            all_flags["NS"] = 1

        return all_flags

    @staticmethod
    def dissect(tcp):
        """Runs all TCP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        ptcp = {} # populate array of connections of Cuckoo default report
        ptcp["layer"] = 4  # Source port
        ptcp["protocol_name"] = "TCP"
        ptcp["sport"] = tcp.sport  # Source port
        ptcp["dport"] = tcp.dport  # Destination port
        ptcp["seqnum"] = tcp.seq  # Sequence number
        ptcp["acknum"] = tcp.ack  # Acknowledge number
        ptcp["off"] = tcp.off  # Data offset
        ptcp["reserved"] = 0  # Reserved - always 0
        ptcp["flags"] = Tcp.tcp_flags(tcp.flags)  # Verify flags of Control Bits (URG,ACK,PSH,RST,SYN,FIN)
        ptcp["win"] = tcp.win  # Window
        ptcp["cksum"] = tcp.sum  # Checksum
        ptcp["urp"] = tcp.urp  # Urgent Pointer
        ptcp["options"] = tcp.opts  # Options
        ptcp["padding"] = ''  # TODO not present in dpkt.ip.IP (maybe computed)

        #TLS/SSL
        # TLS/SSL


        # HTTP
        if http.check(tcp.data):
            ptcp["payload"] = http.dissect(tcp.data)
        # SMTP.
        elif smtp.check(tcp):
            ptcp["payload"] = smtp.dissect(tcp.data)
        # IRC
        elif irc.check(tcp):
            ptcp["payload"] = irc.dissect(tcp.data)
        # DNS
        elif dns.check(tcp):
            ptcp["payload"] = dns.dissect(tcp.data)
        # Unknown Protocol
        else:
            ptcp["payload"] = "unknown protocol on layer " + str(ptcp["layer"]+1)

        return ptcp

