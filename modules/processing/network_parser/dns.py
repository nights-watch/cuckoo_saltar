__author__ = 'targaryen'


import socket

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Dns:

    def __init__(self):
        pass

    @staticmethod
    def check(data):
        """Checks for DNS traffic.
        @param data: UDP or TCP data flow.
        """
        if not (data.dport == 53 or data.sport == 53 or data.dport == 5353 or data.sport == 5353):
            return False
        try:
            dpkt.dns.DNS(data.data)
        except:
            return False

        return True

    @staticmethod
    def dissect(data):
        dns = dpkt.dns.DNS(data)

        pdns = {}

        # Parser of header section of procotol DNS. More information available in topic  4.1.1 of RFC 1035
        pdns["layer"] = 7
        pdns["protocol_name"] = "DNS"
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
        pdns["questions"] = []
        pdns["answers"] = []

        if dns.rcode == dpkt.dns.DNS_RCODE_NOERR or \
                        dns.qr == dpkt.dns.DNS_R or \
                        dns.opcode == dpkt.dns.DNS_QUERY or True:

            for qst in dns.qd:
                try:
                    q_name = qst.name  # QNAME
                    q_type = qst.type  # QTYPE
                    q_class = qst.cls  # QCLASS
                except IndexError:
                    return False

                question={}

                question["class"] = q_class
                question["request"] = q_name
                if q_type == dpkt.dns.DNS_A:
                    question["type"] = "A"
                if q_type == dpkt.dns.DNS_AAAA:
                    question["type"] = "AAAA"
                elif q_type == dpkt.dns.DNS_CNAME:
                    question["type"] = "CNAME"
                elif q_type == dpkt.dns.DNS_MX:
                    question["type"] = "MX"
                elif q_type == dpkt.dns.DNS_PTR:
                    question["type"] = "PTR"
                elif q_type == dpkt.dns.DNS_NS:
                    question["type"] = "NS"
                elif q_type == dpkt.dns.DNS_SOA:
                    question["type"] = "SOA"
                elif q_type == dpkt.dns.DNS_HINFO:
                    question["type"] = "HINFO"
                elif q_type == dpkt.dns.DNS_TXT:
                    question["type"] = "TXT"
                elif q_type == dpkt.dns.DNS_SRV:
                    question["type"] = "SRV"

                # Append query encountered into array index Questions
                pdns["questions"].append(question)

            for answer in dns.an:
                ans = {}
                if answer.type == dpkt.dns.DNS_A: # Topic 3.3.1 of RFC 1035
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
                pdns["answers"].append(ans)

        return pdns
