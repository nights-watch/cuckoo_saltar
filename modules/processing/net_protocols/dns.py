__author__ = 'targaryen'

from lib.cuckoo.common.dns import resolve
from lib.cuckoo.common.config import Config
import socket
import re

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Dns:

    #TODO create singleton
    def __init__(self):
        # List containing all DNS requests.
        self.dns_requests = []
        self.pdns = {}
        self.dns_answers = set()
        # List of unique domains.
        self.unique_domains = []


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

    def check_dns(self, udpdata):
        """Checks for DNS traffic.
        @param udpdata: UDP data flow.
        """
        try:
            dpkt.dns.DNS(udpdata)
        except:
            return False

        return True

    def add_dns(self, udpdata):
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

        self.pdns = {}

        # Parser of header section of procotol DNS. More information available in topic  4.1.1 of RFC 1035

        self.pdns["id"] = ''  # A 16 bit identifier assigned by the program that generates any kind of query.  This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries TODO: Id not implemented on DPKT
        self.pdns["qr"] = dns.qr  # A one bit field that specifies whether this message is a query (0), or a response (1).
        self.pdns["opcode"] = dns.opcode  # kind of query in this message. 0=Standard Query, 1=Inverse Query, 2=Server status and 3-15 reserved for future use
        # AA, TC, RD, RA are flags of DNS package one or more tags are verificate
        self.pdns["aa"] = dns.aa  # Authoritative Answer - valid in responses. Possible values:0=not 1=is
        self.pdns["tc"] = ''  # Truncation TODO: Truncation is not implemented on DPKT to return;
        self.pdns["rd"] = dns.rd  # Recursion Desired. Possible values:0=not 1=is
        self.pdns["ra"] = dns.ra  # Recursion Available. Possible values:0=not 1=is
        self.pdns["z"] = dns.zero  # Reserved for future use. Must be zero
        self.pdns["rcode"] = dns.rcode  # Response Code. 0=No Error, 1=Format error, 2=Server failure, 3=Name Error, 4=Not implemented, 5=Refused. # TODO: Incluir os RCODE descritos nas RFCs 2136, 2671, 2845, 2930, 4635 na biblioteca DPKT
        self.pdns["qdcount"] = len(dns.qd)  # number of entries in the question section
        self.pdns["ancount"] = len(dns.an)  # number of number of resource records in the answer section
        self.pdns["nscount"] = len(dns.ns)  # number of name server resource records in the authority records section
        self.pdns["arcount"] = len(dns.ar)  # number of resource records in the additional records section
        self.pdns["questions"] = []
        self.pdns["answers"] = []
        # DNS query parsing
        query = {}

        if dns.rcode == dpkt.dns.DNS_RCODE_NOERR or \
                        dns.qr == dpkt.dns.DNS_R or \
                        dns.opcode == dpkt.dns.DNS_QUERY or True:
            # DNS question.
            # TODO: revise implementation

            query["questions"] = []

            for question in dns.qd:
                try:
                    q_name = question.name  # QNAME
                    q_type = question.type  # QTYPE
                    q_class = question.cls  # QCLASS
                except IndexError:
                    return False

                qst={}

                qst["request"] = q_name
                if q_type == dpkt.dns.DNS_A:
                    qst["type"] = "A"
                if q_type == dpkt.dns.DNS_AAAA:
                    qst["type"] = "AAAA"
                elif q_type == dpkt.dns.DNS_CNAME:
                    qst["type"] = "CNAME"
                elif q_type == dpkt.dns.DNS_MX:
                    qst["type"] = "MX"
                elif q_type == dpkt.dns.DNS_PTR:
                    qst["type"] = "PTR"
                elif q_type == dpkt.dns.DNS_NS:
                    qst["type"] = "NS"
                elif q_type == dpkt.dns.DNS_SOA:
                    qst["type"] = "SOA"
                elif q_type == dpkt.dns.DNS_HINFO:
                    qst["type"] = "HINFO"
                elif q_type == dpkt.dns.DNS_TXT:
                    qst["type"] = "TXT"
                elif q_type == dpkt.dns.DNS_SRV:
                    qst["type"] = "SRV"

                # Append query encountered into array index Questions
                query["questions"].append(qst)

            self.pdns["questions"] = query["questions"]  # append questions encountered in DNS package

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
                    # Praticamente gera um dicionario de dados da resposta do tipo SOA
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

            self.pdns["answers"]=(query["answers"])  # append answers encountered in DNS package

            #Add te domains uniques in a array
            for question in query["questions"]:
                self._add_domain(question["request"])

        self.dns_requests.append(self.pdns)
        return self.pdns

