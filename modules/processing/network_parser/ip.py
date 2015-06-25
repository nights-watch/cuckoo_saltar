__author__ = 'targaryen'

import socket
from tcp import Tcp as tcp
from udp import Udp as udp
from icmp import Icmp as icmp
from igmp import Igmp as igmp

try:
    import dpkt
    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Ip:

    def __init__(self):
        pass

    def checkv4(self, data):
        if isinstance(data, dpkt.ip.IP):  # RFC 791
            return True
        return False

    def checkv6(self, data):
        if isinstance(data, dpkt.ip6.IP6):  # RFC 791
            return True
        return False

    def dissect(self, ip):
        pip = {}
        ip_flags = {}

        pip["layer"] = 3

        if isinstance(ip, dpkt.ip.IP):  # RFC 791
            pip["protocol_name"] = "IP4"
            pip["ver"] = ip.v_hl
            pip["headsize"] = (ip.v_hl & (0b00001111))  # TODO not present in dpkt.ip.IP (maybe computed)
            pip["tos"] = ip.tos
            pip["pktsize"] = ip.len
            pip["id"] = ip.id
            #pip["flags"] = (ip.off & (0b1110000000000000))>>13  # TODO not present in dpkt.ip.IP (maybe computed)
            ip_flags["reserved"] = (ip.off & (0b1000000000000000))>>15   # TODO not present in dpkt.ip.IP (maybe computed)
            ip_flags["do_not_fragment"] = (ip.off & (0b01000000000000000))>>14  # TODO not present in dpkt.ip.IP (maybe computed)
            ip_flags["more_fragments"] =(ip.off & (0b0010000000000000))>>13  # TODO not present in dpkt.ip.IP (maybe computed)
            pip["flags"] = ip_flags
            pip["offset"] = (ip.off & (0b0001111111111111))<<3
            pip["ttl"] = ip.ttl
            pip["prot"] = ip.p
            pip["ipsum"] = ip.sum
            pip["opts"] = ''  # setted this way on dpkt.ip.IP
            pip["src"] = socket.inet_ntoa(ip.src)
            pip["dst"] = socket.inet_ntoa(ip.dst)
        elif isinstance(ip, dpkt.ip6.IP6):
            pip["protocol_name"] = "IP6"
            pip["procotol"] = "IP"
            pip["ver"] = ip.v
            pip["prio"] = ''  # TODO not present in dpkt.ip6.IP6 (maybe computed)
            pip["flow"] = ''  # TODO not present in dpkt.ip6.IP6 (maybe computed)
            pip["paylen"] = ip.plen
            pip["nexthead"] = ip.nxt
            pip["hoplim"] = ip.hlim
            pip["src"] = socket.inet_ntop(socket.AF_INET6, ip.src)
            pip["dst"] = socket.inet_ntop(socket.AF_INET6, ip.dst)
        if tcp.check(ip.p):
            _tcp = ip.data
            if not isinstance(_tcp, dpkt.tcp.TCP):
                _tcp = dpkt.tcp.TCP(_tcp)
            # if exists data of type TCP realize parser
            # RFC 793
            if len(_tcp.data) > 0:
                pip["payload"] = tcp.dissect(_tcp)

        # if payload of IP is a package UDP
        elif udp.check(ip.p):
            _udp = ip.data
            if not isinstance(_udp, dpkt.udp.UDP):
                _udp = dpkt.udp.UDP(_udp)

            if len(_udp.data) > 0:
                pip["payload"] = udp.dissect(_udp)

        # if payload of IP is a package ICMP
        elif icmp.checkv4(ip.p) or icmp.checkv6(ip.p):
            _icmp = ip.data
            if not isinstance(_icmp, dpkt.icmp.ICMP):
                _icmp = dpkt.icmp.ICMP(_icmp)

            if len(_icmp.data) > 0:
                pip["payload"] = icmp.dissect(_icmp)  # Populate Dictionary ICMP founded and parsed

        # if payload of IP is a package IGMP
        elif igmp.checkv2(ip.p):
                _igmp=ip.data
                if not isinstance(_igmp, dpkt.igmp.IGMP):
                    _igmp=dpkt.igmp.IGMP(_igmp)

                    # if exists data of type IGMP realize parser
                    # RFC 3376 - IGMPv2
                    _igmp=dpkt.igmp.IGMP(_igmp)
                    if len(_igmp.data) > 0:
                        pip["payload"] = igmp.dissect(_igmp)
        else:
            pip["payload"] = "unknown protocol on layer" + str(pip["layer"]+1)

        return pip



