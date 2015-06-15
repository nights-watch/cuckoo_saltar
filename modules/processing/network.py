# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import struct
import socket
import logging
from urlparse import urlunparse

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.dns import resolve
from lib.cuckoo.common.irc import ircMessage
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import convert_to_printable
from lib.cuckoo.common.exceptions import CuckooProcessingError

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

# Imports for the batch sort.
## http://stackoverflow.com/questions/10665925/how-to-sort-huge-files-with-python
## ( http://code.activestate.com/recipes/576755/ )
import heapq
from tempfile import gettempdir
from itertools import islice
from collections import namedtuple

TMPD = gettempdir()
Keyed = namedtuple("Keyed", ["key", "obj"])
Packet = namedtuple("Packet", ["raw", "ts"])


class Pcap:
    """Reads network data from PCAP file."""

    def __init__(self, filepath):
        """Creates a new instance.
        @param filepath: path to PCAP file
        """
        self.filepath = filepath

        # List of all hosts.
        self.hosts = []
        # List containing all non-private IP addresses.
        self.unique_hosts = []
        # List of unique domains.
        self.unique_domains = []
        # List containing all TCP packets.
        self.tcp_connections = []
        self.tcp_connections_seen = set()
        # List containing all UDP packets.
        self.udp_connections = []
        self.udp_connections_seen = set()
        # List containing all ICMP requests.
        self.icmp_requests = []
        # List containing all HTTP requests.
        self.http_requests = {}
        # List containing all DNS requests.
        self.dns_requests = {}
        self.dns_answers = set()
        # List containing all SMTP requests.
        self.smtp_requests = []
        # Reconstruncted SMTP flow.
        self.smtp_flow = {}
        # List containing all IRC requests.
        self.irc_requests = []
        # Dictionary containing all the results of this processing.
        self.results = {}
        # Parser of packages
        self.parser=[]

    def _dns_gethostbyname(self, name):
        """Get host by name wrapper.
        @param name: hostname.
        @return: IP address or blank
        """
        if Config().processing.resolve_dns:
            ip = resolve(name)
        else:
            ip = ""
        return ip

    def _tcp_flags(self, flag):
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

    def _is_private_ip(self, ip):
        """Check if the IP belongs to private network blocks.
        @param ip: IP address to verify.
        @return: boolean representing whether the IP belongs or not to
                 a private network block.
        """
        networks = [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "240.0.0.0/4",
            "255.255.255.255/32",
            "224.0.0.0/4"
        ]

        for network in networks:
            try:
                ipaddr = struct.unpack(">I", socket.inet_aton(ip))[0]

                netaddr, bits = network.split("/")

                network_low = struct.unpack(">I", socket.inet_aton(netaddr))[0]
                network_high = network_low | (1 << (32 - int(bits))) - 1

                if ipaddr <= network_high and ipaddr >= network_low:
                    return True
            except:
                continue

        return False

    def _add_hosts(self, connection):
        """Add IPs to unique list.
        @param connection: connection data
        """
        try:
            if connection["src"] not in self.hosts:
                ip = convert_to_printable(connection["src"])

                # We consider the IP only if it hasn't been seen before.
                if ip not in self.hosts:
                    # If the IP is not a local one, this might be a leftover
                    # packet as described in issue #249.
                    if self._is_private_ip(ip):
                        self.hosts.append(ip)

            if connection["dst"] not in self.hosts:
                ip = convert_to_printable(connection["dst"])

                if ip not in self.hosts:
                    self.hosts.append(ip)

                    # We add external IPs to the list, only the first time
                    # we see them and if they're the destination of the
                    # first packet they appear in.
                    if not self._is_private_ip(ip):
                        self.unique_hosts.append(ip)
        except:
            pass

    def _tcp_dissect(self, conn, data):
        """Runs all TCP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        # HTTP
        if self._check_http(data):
            return self._add_http(data, conn["dport"])
        # SMTP.
        elif conn["dport"] == 25:
            return self._reassemble_smtp(conn, data)
        # IRC.
        elif conn["dport"] != 21 and self._check_irc(data):
            return self._add_irc(data)
        # Another protocol unknown
        else:
            return "unknown protocol"

    def _udp_dissect(self, conn, data):
        """Runs all UDP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        # Select DNS and MDNS traffic.
        # According of RFC 1035:
        #
        # The DNS assumes that messages will be transmitted as datagrams or in a
        # byte stream carried by a virtual circuit.  While virtual circuits can be
        # used for any DNS activity, datagrams are preferred for queries due to
        # their lower overhead and better performance.  Zone refresh activities
        # must use virtual circuits because of the need for reliable transfer.

        # The Internet supports name server access using TCP [RFC-793] on server
        # port 53 (decimal) as well as datagram access using UDP [RFC-768] on UDP
        # port 53 (decimal).,
        if conn["dport"] == 53 or conn["sport"] == 53 or conn["dport"] == 5353 or conn["sport"] == 5353:
            if self._check_dns(data):
                return self._add_dns(data)

    def _check_icmp(self, icmp_data):
        """Checks for ICMP traffic.
        @param icmp_data: ICMP data flow.
        """
        try:
            return isinstance(icmp_data, dpkt.icmp.ICMP) and \
                   len(icmp_data.data) > 0
        except:
            return False

    def _icmp_dissect(self, conn, data):
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

    def _check_dns(self, udpdata):
        """Checks for DNS traffic.
        @param udpdata: UDP data flow.
        """
        try:
            dpkt.dns.DNS(udpdata)
        except:
            return False

        return True

    def _add_dns(self, udpdata):
        """Adds a DNS data flow.
        @param udpdata: UDP data flow.

        Struture of DNS Package
        |-------------------------------------------------------------------------------------------------------------------------------|
        |00	|01	|02	|03	|04	|05	|06	|07	|08	|09	|10	|11	|12	|13	|14	|15 |16	|17	|18	|19	|20	|21	|22	|23	|24	|25	|26	|27	|28	|29	|30	|31 |
        |-------------------------------------------------------------------------------------------------------------------------------|
        |                        Identification                         |QR |   Opcode 	    |AA	|TC |RD |RA |Z 	|AD |CD |     Rcode     |
        |-------------------------------------------------------------------------------------------------------------------------------|
        |                       Total Questions 	                    |                       Total Answer RRs                        |
        |-------------------------------------------------------------------------------------------------------------------------------|
        |                       Total Authority RRs 	                |                      Total Additional RRs                     |
        |-------------------------------------------------------------------------------------------------------------------------------|
        |                                                       Questions [] :::                                                        |
        |                                        # Question section format                                                              |
        |                                        #                                1  1  1  1  1  1                                      |
        |                                        #  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5                                      |
        |                                        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+                                    |
        |                                        # |                                               |                                    |
        |                                        # /                     QNAME                     /                                    |
        |                                        # /                                               /                                    |
        |                                        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+                                    |
        |                                        # |                     QTYPE                     |                                    |
        |                                        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+                                    |
        |                                        # |                     QCLASS                    |                                    |
        |                                        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+                                    |
        |                                                                                                                               |
        |-------------------------------------------------------------------------------------------------------------------------------|
        |                                                       Answer RRs [] :::                                                       |
        |                                         DNS answer - can be repeat n times                                                    |
        |                                         Answers section format                                                                |
        |                                                                        1  1  1  1  1  1                                       |
        |                                         0   1  2  3  4  5  6  7  8  9  0  1  2  3  4  5                                       |
        |                                        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+                                      |
        |                                        /                  NAME                        /|                                      |
        |                                        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+                                      |
        |                                        |                  TYPE                         |                                      |
        |                                        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+                                      |
        |                                        |                  CLASS                        |                                      |
        |                                        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+                                      |
        |                                        |                  TTL                          |                                      |
        |                                        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+                                      |
        |                                        |                  RDLENGTH                     |                                      |
        |                                        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|                                      |
        |                                        /                  RDATA /                      |                                      |
        |                                        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+                                      |
        |-------------------------------------------------------------------------------------------------------------------------------|
        |                                                      Authority RRs [] :::                                                     |
        |-------------------------------------------------------------------------------------------------------------------------------|
        |                                                     Additional RRs [] :::                                                     |
        |-------------------------------------------------------------------------------------------------------------------------------|

        RFC References for project SALTAR
        RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION - https://www.ietf.org/rfc/rfc1035
        RFC 2136 - Dynamic Updates in the Domain Name System (DNS UPDATE) - https://www.ietf.org/rfc/rfc2136
        RFC 2671 - Extension Mechanisms for DNS (EDNS0) - https://www.ietf.org/rfc/rfc2671.txt
        RFC 2845 - Secret Key Transaction Authentication for DNS (TSIG) -https://www.ietf.org/rfc/rfc2845
        RFC 2930 - Secret Key Establishment for DNS (TKEY RR) - https://tools.ietf.org/html/rfc2930
        RFC 3596 - NS Extensions to Support IP Version 6 - https://tools.ietf.org/html//rfc3596
        RFC 4635 -  HMAC SHA TSIG Algorithm Identifiers -  https://tools.ietf.org/html/rfc4635
        RFC 6895 - Domain Name System (DNS) IANA Considerations - https://tools.ietf.org/html/rfc6195

        Additional reference: http://www.networksorcery.com/enp/protocol/dns.htm


        """
        dns = dpkt.dns.DNS(udpdata)

        pdns = {}

        # Parser of header section of procotol DNS. More information available in topic  4.1.1 of RFC 1035

        pdns["id"] = ''  # A 16 bit identifier assigned by the program that generates any kind of query.  This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries TODO: Id not implemented on DPKT
        pdns["qr"] = dns.qr  # A one bit field that specifies whether this message is a query (0), or a response (1).
        pdns["opcode"] = dns.opcode  # kind of query in this message. 0=Standard Query, 1=Inverse Query, 2=Server status and 3-15 reserved for future use
        # AA, TC, RD, RA are flags of DNS package one or more tags are verificate
        pdns["aa"] = dns.aa  # Authoritative Answer - valid in responses. Possible values:0=not 1=is
        pdns["tc"] = ''  # Truncation TODO: Truncation is not implemented on DPKT to return;
        pdns["rd"] = dns.rd  # Recursion Desired. Possible values:0=not 1=is
        pdns["ra"] = dns.ra  # Recursion Available. Possible values:0=not 1=is
        pdns["z"] = dns.zero  # Reserved for future use. Must be zero
        pdns["rcode"] = dns.rcode  # Response Code. 0=No Error, 1=Format error, 2=Server failure, 3=Name Error, 4=Not implemented, 5=Refused. # TODO: Incluir os RCODE descritos nas RFCs 2136, 2671, 2845, 2930, 4635 na biblioteca DPKT
        pdns["qdcount"] = len(dns.qd)  # number of entries in the question section
        pdns["ancount"] = len(dns.an)  # number of number of resource records in the answer section
        pdns["nscount"] = len(dns.ns)  # number of name server resource records in the authority records section
        pdns["arcount"] = len(dns.ar)  # number of resource records in the additional records section

        # DNS query parsing
        query = {}

        if dns.rcode == dpkt.dns.DNS_RCODE_NOERR or \
                        dns.qr == dpkt.dns.DNS_R or \
                        dns.opcode == dpkt.dns.DNS_QUERY or True:
            # DNS question.
            # TODO: revisar implementação
            for question in dns.qd:
                try:
                    q_name = dns.qd[0].name  # QNAME
                    q_type = dns.qd[0].type  # QTYPE
                    q_class = dns.qd[0].cls  # QCLASS
                except IndexError:
                    return False
                query["questions"] = []

                query["request"] = q_name
                if q_type == dpkt.dns.DNS_A:
                    query["type"] = "A"
                if q_type == dpkt.dns.DNS_AAAA:
                    query["type"] = "AAAA"
                elif q_type == dpkt.dns.DNS_CNAME:
                    query["type"] = "CNAME"
                elif q_type == dpkt.dns.DNS_MX:
                    query["type"] = "MX"
                elif q_type == dpkt.dns.DNS_PTR:
                    query["type"] = "PTR"
                elif q_type == dpkt.dns.DNS_NS:
                    query["type"] = "NS"
                elif q_type == dpkt.dns.DNS_SOA:
                    query["type"] = "SOA"
                elif q_type == dpkt.dns.DNS_HINFO:
                    query["type"] = "HINFO"
                elif q_type == dpkt.dns.DNS_TXT:
                    query["type"] = "TXT"
                elif q_type == dpkt.dns.DNS_SRV:
                    query["type"] = "SRV"

                # Append query encountered into array index Questions
                query["questions"].append(question)

            pdns["questions"].append(query["questions"])  # append questions encountered in DNS package

            #  Dns answers
            query["answers"] = []
            for answer in dns.an:
                ans = {}
                if answer.type == dpkt.dns.DNS_A:
                    # Topic 3.3.1 of RFC 1035
                    ans["type"] = "A"
                    try:
                        ans["data"] = socket.inet_ntoa(answer.rdata)
                    except socket.error:
                        continue
                elif answer.type == dpkt.dns.DNS_AAAA:
                    #Reference of Topic 3.3.1 of RFC 1035. The same, but for IPv6
                    ans["type"] = "AAAA"
                    try:
                        ans["data"] = socket.inet_ntop(socket.AF_INET6,
                                                       answer.rdata)
                    except (socket.error, ValueError):
                        continue
                elif answer.type == dpkt.dns.DNS_CNAME:
                    #Topic 3.3.1 of RFC 1035
                    ans["type"] = "CNAME"
                    ans["data"] = answer.cname
                elif answer.type == dpkt.dns.DNS_MX:
                    #Topic 3.3.9 of RFC 1035
                    ans["type"] = "MX"
                    ans["data"] = answer.mxname
                elif answer.type == dpkt.dns.DNS_PTR:
                    #Topic 3.3.12 of RFC 1035
                    ans["type"] = "PTR"
                    ans["data"] = answer.ptrname
                elif answer.type == dpkt.dns.DNS_NS:
                    # Topic 3.3.11 of RFC 1035
                    ans["type"] = "NS"
                    ans["data"] = answer.nsname
                elif answer.type == dpkt.dns.DNS_SOA:
                    # Topic 3.3.13 of RFC 1035
                    ans["type"] = "SOA"
                    # Parser SOA
                    # Praticamente gera um dicionário de dados da resposta do tipo SOA
                    # Primary NS 	    Variable length. The name of the Primary Master for the domain. May be a label, pointer or any combination.
                    # Admin MB 	        Variable length. The administrator's mailbox. May be a label, pointer or any combination.
                    # Serial Number 	Unsigned 32-bit integer.
                    # Refresh interval 	Unsigned 32-bit integer.
                    # Retry Interval 	Unsigned 32-bit integer.
                    # Expiration Limit 	Unsigned 32-bit integer.
                    # Minimum TTL    	Unsigned 32-bit integer.
                    ans["data"] = ",".join([answer.mname,
                                            answer.rname,
                                            str(answer.serial),
                                            str(answer.refresh),
                                            str(answer.retry),
                                            str(answer.expire),
                                            str(answer.minimum)])
                elif answer.type == dpkt.dns.DNS_HINFO:
                    #Topic 3.3.2 of RFC 1035
                    ans["type"] = "HINFO"
                    ans["data"] = " ".join(answer.text)
                elif answer.type == dpkt.dns.DNS_TXT:
                    #Topic 3.3.14 of RFC 1035
                    ans["type"] = "TXT"
                    ans["data"] = " ".join(answer.text)

                # TODO: add srv handling
                query["answers"].append(ans)

            pdns["answers"].append(query["answers"])  # append answers encountered in DNS package

            #Add te domains uniques in a array
            self._add_domain(query["request"])

            #Format a tuple of requisition DNS.For use of default report Cuckoo
            reqtuple = (query["type"], query["request"])
            if not reqtuple in self.dns_requests:
                self.dns_requests[reqtuple] = query
            else:
                new_answers = set((i["type"], i["data"]) for i in query["answers"]) - self.dns_answers
                self.dns_requests[reqtuple]["answers"] += [dict(type=i[0], data=i[1]) for i in new_answers]

        return pdns

    def _add_domain(self, domain):
        """Add a domain to unique list.
        @param domain: domain name.
        """
        filters = [
            ".*\\.windows\\.com$",
            ".*\\.in\\-addr\\.arpa$"
        ]

        regexps = [re.compile(filter) for filter in filters]
        for regexp in regexps:
            if regexp.match(domain):
                return

        for entry in self.unique_domains:
            if entry["domain"] == domain:
                return

        self.unique_domains.append({"domain": domain,
                                    "ip": self._dns_gethostbyname(domain)})

    def _check_http(self, tcpdata):
        """Checks for HTTP traffic.
        @param tcpdata: TCP data flow.
        """
        try:
            r = dpkt.http.Request()
            r.method, r.version, r.uri = None, None, None
            r.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            if not r.method is None or not r.version is None or \
                    not r.uri is None:
                return True
            return False

        return True

    def _add_http(self, tcpdata, dport):
        """Adds an HTTP flow.
        @param tcpdata: TCP data flow.
        @param dport: destination port.
        """
        if tcpdata in self.http_requests:
            self.http_requests[tcpdata]["count"] += 1
            return True

        try:
            http = dpkt.http.Request()
            http.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            pass

        try:
            entry = {"count": 1}

            if "host" in http.headers:
                entry["host"] = convert_to_printable(http.headers["host"])
            else:
                entry["host"] = ""

            entry["port"] = dport

            # Manually deal with cases when destination port is not the default one,
            # and it is  not included in host header.
            netloc = entry["host"]
            if dport != 80 and ":" not in netloc:
                netloc += ":" + str(entry["port"])

            entry["data"] = convert_to_printable(tcpdata)
            entry["uri"] = convert_to_printable(urlunparse(("http",
                                                            netloc,
                                                            http.uri, None,
                                                            None, None)))
            entry["body"] = convert_to_printable(http.body)
            entry["path"] = convert_to_printable(http.uri)

            if "user-agent" in http.headers:
                entry["user-agent"] = \
                    convert_to_printable(http.headers["user-agent"])

            entry["version"] = convert_to_printable(http.version)
            entry["method"] = convert_to_printable(http.method)

            self.http_requests[tcpdata] = entry
        except Exception:
            return False

        return True

    def _reassemble_smtp(self, conn, data):
        """Reassemble a SMTP flow.
        @param conn: connection dict.
        @param data: raw data.
        """
        if conn["dst"] in self.smtp_flow:
            self.smtp_flow[conn["dst"]] += data
        else:
            self.smtp_flow[conn["dst"]] = data

    def _process_smtp(self):
        """Process SMTP flow."""
        #RFC 2821
        for conn, data in self.smtp_flow.iteritems():
            # Detect new SMTP flow.
            if data.startswith("EHLO") or data.startswith("HELO"):
                self.smtp_requests.append({"dst": conn, "raw": data})

    def _check_irc(self, tcpdata):
        """
        Checks for IRC traffic.
        Identify
        @param tcpdata: tcp data flow
        """
        try:
            req = ircMessage()
        except Exception:
            return False

        return req.isthereIRC(tcpdata)

    def _add_irc(self, tcpdata):
        """
        RFC 1459 - Internet Relay Chat Protocol - https://tools.ietf.org/html/rfc1459

        Adds an IRC communication.
        @param tcpdata: TCP data in flow
        @param dport: destination port
        """
        pirc={}
        irc_request=[]
        try:
            reqc = ircMessage()
            reqs = ircMessage()
            filters_sc = ["266"]
            self.irc_requests = self.irc_requests + \
                                reqc.getClientMessages(tcpdata) + \
                                reqs.getServerMessagesFilter(tcpdata, filters_sc)
            irc_request=self.irc_requests
        except Exception:
            return "Can't retrieve IRC messages from TCP data"

        return irc_request

    def run(self):
        """Process PCAP.
        @return: dict with network analysis data.
        """
        log = logging.getLogger("Processing.Pcap")

        if not IS_DPKT:
            log.error("Python DPKT is not installed, aborting PCAP analysis.")
            return self.results

        if not os.path.exists(self.filepath):
            log.warning("The PCAP file does not exist at path \"%s\".",
                        self.filepath)
            return self.results

        if os.path.getsize(self.filepath) == 0:
            log.error("The PCAP file at path \"%s\" is empty." % self.filepath)
            return self.results

        try:
            file = open(self.filepath, "rb")
        except (IOError, OSError):
            log.error("Unable to open %s" % self.filepath)
            return self.results

        try:
            pcap = dpkt.pcap.Reader(file)
        except dpkt.dpkt.NeedData:
            log.error("Unable to read PCAP file at path \"%s\".",
                      self.filepath)
            return self.results
        except ValueError:
            log.error("Unable to read PCAP file at path \"%s\". File is "
                      "corrupted or wrong format." % self.filepath)
            return self.results

        offset = file.tell()
        first_ts = None
        for ts, buf in pcap:

            if not first_ts: first_ts = ts
            try:
                ip = iplayer_from_raw(buf, pcap.datalink())

                connection = {}
                package={}
                pip = {}
                ptcp = {}
                pudp = {}
                picmp = {}
                psmtp = {}
                phttp = {}
                if isinstance(ip, dpkt.ip.IP):  # RFC 791
                    pip["ver"] = ip.v_hl
                    pip["headsize"] = ''  # TODO not present in dpkt.ip.IP (maybe computed)
                    pip["tos"] = ip.tos
                    pip["pktsize"] = ip.len
                    pip["id"] = ip.id
                    pip["flags"] = ''  # TODO not present in dpkt.ip.IP (maybe computed)
                    pip["offset"] = ip.off
                    pip["ttl"] = ip.ttl
                    pip["prot"] = ip.p
                    pip["ipsum"] = ip.sum
                    pip["opts"] = ''  # setted this way on dpkt.ip.IP
                    pip["src"] = socket.inet_ntoa(ip.src)
                    pip["dst"] = socket.inet_ntoa(ip.dst)
                    connection["src"] = socket.inet_ntoa(ip.src)
                    connection["dst"] = socket.inet_ntoa(ip.dst)
                elif isinstance(ip, dpkt.ip6.IP6):  # RFC 1883 (w/o extension headers)
                    pip["procotol"] = "IP"
                    pip["ver"] = ip.v
                    pip["prio"] = ''  # TODO not present in dpkt.ip6.IP6 (maybe computed)
                    pip["flow"] = ''  # TODO not present in dpkt.ip6.IP6 (maybe computed)
                    pip["paylen"] = ip.plen
                    pip["nexthead"] = ip.nxt
                    pip["hoplim"] = ip.hlim
                    pip["src"] = socket.inet_ntop(socket.AF_INET6, ip.src)
                    pip["dst"] = socket.inet_ntop(socket.AF_INET6, ip.dst)
                    connection["src"] = socket.inet_ntop(socket.AF_INET6, ip.src)
                    connection["dst"] = socket.inet_ntop(socket.AF_INET6, ip.dst)
                else:
                    offset = file.tell()
                    continue

                self._add_hosts(connection)
                # if payload of IP is a package TCP
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    if not isinstance(tcp, dpkt.tcp.TCP):
                        tcp = dpkt.tcp.TCP(tcp)
                        # if exists data of type TCP realize parser
                    # RFC 793
                    if len(tcp.data) > 0:
                        # populate array of connections of Cuckoo default report
                        connection["sport"] = tcp.sport  # Source port
                        connection["dport"] = tcp.dport  # Destination port
                        ptcp["sport"] = tcp.sport  # Source port
                        ptcp["dport"] = tcp.dport  # Destination port
                        ptcp["seqnum"] = tcp.seq  # Sequence number
                        ptcp["acknum"] = tcp.flags  # Acknowledge number
                        ptcp["off"] = tcp.off  # Data offset
                        ptcp["reserved"] = 0  # Reserved - always 0
                        ptcp["cb"] = self._tcp_flags(tcp.data)  # Verify flag of control bits
                        ptcp["win"] = tcp.win  # Window
                        ptcp["cksum"] = tcp.sum  # Checksum
                        ptcp["urp"] = tcp.urp  # Urgent Pointer
                        ptcp["options"] = tcp.opts  # Options
                        ptcp["padding"] = ''  # TODO not present in dpkt.ip.IP (maybe computed)
                        ptcp["payload"] = self._tcp_dissect(connection, tcp.data)  # Verify payload of package TCP

                        # Populate list of TCP Connections, default of Cuckoo sandbox
                        src, sport, dst, dport = (
                            connection["src"], connection["sport"], connection["dst"], connection["dport"])
                        if not ((dst, dport, src, sport) in self.tcp_connections_seen or (
                                src, sport, dst, dport) in self.tcp_connections_seen):
                            self.tcp_connections.append((src, sport, dst, dport, offset, ts - first_ts))
                            self.tcp_connections_seen.add((src, sport, dst, dport))
                # if payload of IP is a package UDP
                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    udp = ip.data
                    if not isinstance(udp, dpkt.udp.UDP):
                        udp = dpkt.udp.UDP(udp)

                    if len(udp.data) > 0:
                        # if exists data of type UDP realize parser
                        # RFC 768
                        connection["sport"] = udp.sport  # Source port
                        connection["dport"] = udp.dport  # Destination port
                        pudp["sport"] = udp.sport  # Source port
                        pudp["dport"] = udp.dport  # Destination port
                        pudp["ulen"] = udp.ulen  # Length
                        pudp["usum"] = udp.sum  # Checksum
                        pudp["payload"]=self._udp_dissect(connection, udp.data)  # Data Octets - Payload

                        # Populate list of UDP Connections, default of Cuckoo sandbox
                        src, sport, dst, dport = (
                            connection["src"], connection["sport"], connection["dst"], connection["dport"])
                        if not ((dst, dport, src, sport) in self.udp_connections_seen or (
                                src, sport, dst, dport) in self.udp_connections_seen):
                            self.udp_connections.append((src, sport, dst, dport, offset, ts - first_ts))
                            self.udp_connections_seen.add((src, sport, dst, dport))

                # if payload of IP is a package ICMP
                elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                    icmp = ip.data
                    if not isinstance(icmp, dpkt.icmp.ICMP):
                        icmp = dpkt.icmp.ICMP(icmp)

                    picmp = self._icmp_dissect(connection, icmp)  # Populate Dictionary ICMP founded and parsed

                offset = file.tell()
            except AttributeError:
                continue
            except dpkt.dpkt.NeedData:
                continue
            except Exception as e:
                log.exception("Failed to process packet: %s", e)

        file.close()

        # Post processors for reconstructed flows.
        self._process_smtp()

        # Build results dict.
        self.results["hosts"] = self.unique_hosts
        self.results["domains"] = self.unique_domains
        self.results["tcp"] = [conn_from_flowtuple(i) for i in self.tcp_connections]
        self.results["udp"] = [conn_from_flowtuple(i) for i in self.udp_connections]
        self.results["icmp"] = self.icmp_requests
        self.results["http"] = self.http_requests.values()
        self.results["dns"] = self.dns_requests.values()
        self.results["smtp"] = self.smtp_requests
        self.results["irc"] = self.irc_requests
        self.results["pcap_parser"] = [self.parser]

        return self.results


class NetworkAnalysis(Processing):
    """Network analysis."""

    def run(self):
        self.key = "network"

        sorted_path = self.pcap_path.replace("dump.", "dump_sorted.")
        if Config().processing.sort_pcap:
            sort_pcap(self.pcap_path, sorted_path)
            results = Pcap(sorted_path).run()
        else:
            results = Pcap(self.pcap_path).run()

        # Save PCAP file hash.
        if os.path.exists(self.pcap_path):
            results["pcap_sha256"] = File(self.pcap_path).get_sha256()
        if os.path.exists(sorted_path):
            results["sorted_pcap_sha256"] = File(sorted_path).get_sha256()

        return results


def iplayer_from_raw(raw, linktype=1):
    """Converts a raw packet to a dpkt packet regarding of link type.
    @param raw: raw packet
    @param linktype: integer describing link type as expected by dpkt
    """
    if linktype == 1:  # ethernet
        pkt = dpkt.ethernet.Ethernet(raw)
        ip = pkt.data
    elif linktype == 101:  # raw
        ip = dpkt.ip.IP(raw)
    else:
        raise CuckooProcessingError("unknown PCAP linktype")
    return ip


def conn_from_flowtuple(ft):
    """Convert the flow tuple into a dictionary (suitable for JSON)"""
    sip, sport, dip, dport, offset, relts = ft
    return {"src": sip, "sport": sport, "dst": dip, "dport": dport, "offset": offset, "time": relts}


def packet_from_flowtuple(packet):
    """Convert the flow tuple into a dictionary JSON"""


# input_iterator should be a class that als supports writing so we can use it for the temp files
# this code is mostly taken from some SO post, can't remember the url though
def batch_sort(input_iterator, output_path, buffer_size=32000, output_class=None):
    """batch sort helper with temporary files, supports sorting large stuff"""
    if not output_class:
        output_class = input_iterator.__class__

    chunks = []
    try:
        while True:
            current_chunk = list(islice(input_iterator, buffer_size))
            if not current_chunk:
                break
            current_chunk.sort()
            output_chunk = output_class(os.path.join(TMPD, "%06i" % len(chunks)))
            chunks.append(output_chunk)

            for elem in current_chunk:
                output_chunk.write(elem.obj)
            output_chunk.close()

        output_file = output_class(output_path)
        for elem in heapq.merge(*chunks):
            output_file.write(elem.obj)
        output_file.close()
    finally:
        for chunk in chunks:
            try:
                chunk.close()
                os.remove(chunk.name)
            except Exception:
                pass


# magic
class SortCap(object):
    """SortCap is a wrapper around the packet lib (dpkt) that allows us to sort pcaps
    together with the batch_sort function above."""

    def __init__(self, path, linktype=1):
        self.name = path
        self.linktype = linktype
        self.fd = None
        self.ctr = 0  # counter to pass through packets without flow info (non-IP)
        self.conns = set()

    def write(self, p):
        if not self.fd:
            self.fd = dpkt.pcap.Writer(open(self.name, "wb"), linktype=self.linktype)
        self.fd.writepkt(p.raw, p.ts)

    def __iter__(self):
        if not self.fd:
            self.fd = dpkt.pcap.Reader(open(self.name, "rb"))
            self.fditer = iter(self.fd)
            self.linktype = self.fd.datalink()
        return self

    def close(self):
        self.fd.close()
        self.fd = None

    def next(self):
        rp = next(self.fditer)
        if rp is None: return None
        self.ctr += 1

        ts, raw = rp
        rpkt = Packet(raw, ts)

        sip, dip, sport, dport, proto = flowtuple_from_raw(raw, self.linktype)

        # check other direction of same flow
        if (dip, sip, dport, sport, proto) in self.conns:
            flowtuple = (dip, sip, dport, sport, proto)
        else:
            flowtuple = (sip, dip, sport, dport, proto)

        self.conns.add(flowtuple)
        return Keyed((flowtuple, ts, self.ctr), rpkt)


def sort_pcap(inpath, outpath):
    """Use SortCap class together with batch_sort to sort a pcap"""
    inc = SortCap(inpath)
    batch_sort(inc, outpath, output_class=lambda path: SortCap(path, linktype=inc.linktype))
    return 0


def flowtuple_from_raw(raw, linktype=1):
    """Parse a packet from a pcap just enough to gain a flow description tuple"""
    ip = iplayer_from_raw(raw, linktype)

    # Verify if package contain IP protocol
    if isinstance(ip, dpkt.ip.IP):
        # ver = Version of format of the Internet Header
        # hl = Internet Header Lenght (IHL)
        # sip = Source IP
        # dip = Destination IP
        # opt = Options
        # pad = Padding
        sip, dip = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
        proto = ip.p

        if proto == dpkt.ip.IP_PROTO_TCP or proto == dpkt.ip.IP_PROTO_UDP:
            l3 = ip.data
            sport, dport = l3.sport, l3.dport
        else:
            sport, dport = 0, 0

    else:
        sip, dip, proto = 0, 0, -1
        sport, dport = 0, 0

    flowtuple = (sip, dip, sport, dport, proto)
    return flowtuple


def payload_from_raw(raw, linktype=1):
    """Get the payload from a packet, the data below TCP/UDP basically"""
    ip = iplayer_from_raw(raw, linktype)
    try:
        return ip.data.data
    except:
        return ""


def next_connection_packets(piter, linktype=1):
    """Extract all packets belonging to the same flow from a pcap packet iterator"""
    first_ft = None

    for ts, raw in piter:
        ft = flowtuple_from_raw(raw, linktype)
        if not first_ft: first_ft = ft

        sip, dip, sport, dport, proto = ft
        if not (first_ft == ft or first_ft == (dip, sip, dport, sport, proto)):
            break

        yield {
            "src": sip, "dst": dip, "sport": sport, "dport": dport,
            "raw": payload_from_raw(raw, linktype).encode("base64"), "direction": first_ft == ft,
        }


def packets_for_stream(fobj, offset):
    """Open a PCAP, seek to a packet offset, then get all packets belonging to the same connection"""
    pcap = dpkt.pcap.Reader(fobj)
    pcapiter = iter(pcap)
    ts, raw = pcapiter.next()

    fobj.seek(offset)
    for p in next_connection_packets(pcapiter, linktype=pcap.datalink()):
        yield p


def package_json(package):
    """
     Create a hierarchical package i
format to json
    """
