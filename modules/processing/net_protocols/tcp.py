__author__ = 'targaryen'

import http
import smtp
import irc
import dns

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Tcp:

    def __init__(self, pcap):
        self.pcap = pcap
        # List containing all TCP packets.
        self.tcp_connections = []
        self.tcp_connections_seen = set()
        self.http = http.Http()
        self.smtp = smtp.Smtp()
        self.irc = irc.Irc()
        self.dns = dns.Dns()


    def tcp_dissect(self, conn, data):
        """Runs all TCP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        # HTTP
        if self.pcap.http.check_http(data):
            return self.pcap.http.add_http(data, conn["dport"])
        # SMTP.
        elif conn["dport"] == 25:
            return self.pcap.smtp.reassemble_smtp()
        elif conn["dport"] != 21 and self.irc.check_irc(data):
            return self.pcap.irc.add_irc(data)
        # Another protocol unknown
        else:
            return "unknown protocol"

    def tcp_flags(self, flag):
        """Identify flag TCP of a packet."""
        flagreturn = ''
        if flag == dpkt.tcp.TH_FYN:
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


