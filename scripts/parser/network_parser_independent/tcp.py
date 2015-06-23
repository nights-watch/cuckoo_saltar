__author__ = 'targaryen'

from http import Http as http
from smtp import Smtp as smtp
from irc import Irc as irc
from dns import Dns as dns

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
    def tcp_flags(flag):
        """Identify flag TCP of a packet."""
        flagreturn = ''
        if flag == dpkt.tcp.TH_FIN:
            flagreturn = "FIN"
        elif flag == dpkt.tcp.TH_SYN:
            flagreturn = "SYN"
        elif flag == dpkt.tcp.TH_RST:
            flagreturn = "RST"
        elif flag == dpkt.tcp.TH_PUSH:
            flagreturn = "PUS"
        elif flag == dpkt.tcp.TH_ACK:
            flagreturn = "ACK"
        elif flag == dpkt.tcp.TH_URG:
            flagreturn = "URG"
        elif flag == dpkt.tcp.TH_ECE:
            flagreturn = "ECE"
        elif flag == dpkt.tcp.TH_CWR:
            flagreturn = "CWR"
        else:
            flagreturn = "UNK"

        return flagreturn

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
        ptcp["acknum"] = tcp.flags  # Acknowledge number
        ptcp["off"] = tcp.off  # Data offset
        ptcp["reserved"] = 0  # Reserved - always 0
        ptcp["cb"] = Tcp.tcp_flags(tcp.data)  # Verify flag of control bits
        ptcp["win"] = tcp.win  # Window
        ptcp["cksum"] = tcp.sum  # Checksum
        ptcp["urp"] = tcp.urp  # Urgent Pointer
        ptcp["options"] = tcp.opts  # Options
        ptcp["padding"] = ''  # TODO not present in dpkt.ip.IP (maybe computed)

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

