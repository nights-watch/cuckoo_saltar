# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import socket
import logging
from net_protocols import smtp
from net_protocols import http
from net_protocols import irc
from net_protocols import dns
from net_protocols import icmp
from net_protocols import udp
from net_protocols import tcp
from net_protocols import ip

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config

from lib.cuckoo.common.objects import File
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

        self.smtp = smtp.Smtp()
        self.http = http.Http()
        self.irc = irc.Irc()
        self.dns = dns.Dns()
        self.icmp = icmp.Icmp()
        self.udp = udp.Udp()
        self.tcp = tcp.Tcp(self)
        self.ip = ip.Ip()

        # Dictionary containing all the results of this processing.
        self.results = {}
        # Parser of packages
        self.parser = []

    def readPcap(self):
        """Process PCAP.
        @return: dict with network analysis data.
        """
        log = logging.getLogger("Processing.Pcap")

        if not IS_DPKT:
            log.error("Python DPKT is not installed, aborting PCAP analysis.")
            return None

        if not os.path.exists(self.filepath):
            log.warning("The PCAP file does not exist at path \"%s\".",
                        self.filepath)
            return None

        if os.path.getsize(self.filepath) == 0:
            log.error("The PCAP file at path \"%s\" is empty." % self.filepath)
            return None

        try:
            with open(self.filepath, "rb") as file:
                pcap = dpkt.pcap.Reader(file)
                return pcap
        except dpkt.dpkt.NeedData:
            log.error("Unable to read PCAP file at path \"%s\".",
                      self.filepath)
        except (IOError, OSError):
            log.error("Unable to open %s" % self.filepath)
        except ValueError:
            log.error("Unable to read PCAP file at path \"%s\". File is "
                      "corrupted or wrong format." % self.filepath)
        return None

    def run(self):
        log = logging.getLogger("Processing.Pcap")

        result = {}
        pcap = self.readPcap()

        if pcap is None:
            return {}
        first_ts = None

        pcapLine = 0

        for ts, buf in pcap:
            pcapLine += 1
            try:
                ip = iplayer_from_raw(buf, pcap.datalink())

                if isinstance(ip, dpkt.ip.IP):  # RFC 791
                    result[pcapLine] = self.ip.dissect(ip)
                elif isinstance(ip, dpkt.ip6.IP6):
                    result[pcapLine] = self.ipV6.dissect(ip)
                else:
                    continue

            except AttributeError:
                continue
            except dpkt.dpkt.NeedData:
                continue
            except Exception as e:
                log.exception("Failed to process packet: %s", e)

        saida = self.run2();
        self.results["parser"] = result

        return self.results

    def run2(self):
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

            if not first_ts:
                first_ts = ts
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

                self.ip.add_hosts(connection)
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
                        ptcp["cb"] = self.tcp.tcp_flags(tcp.data)  # Verify flag of control bits
                        ptcp["win"] = tcp.win  # Window
                        ptcp["cksum"] = tcp.sum  # Checksum
                        ptcp["urp"] = tcp.urp  # Urgent Pointer
                        ptcp["options"] = tcp.opts  # Options
                        ptcp["padding"] = ''  # TODO not present in dpkt.ip.IP (maybe computed)
                        ptcp["payload"] = self.tcp.tcp_dissect(connection, tcp.data)  # Verify payload of package TCP

                        # # Populate list of TCP Connections, default of Cuckoo sandbox
                        # src, sport, dst, dport = (
                        #     connection["src"], connection["sport"], connection["dst"], connection["dport"])
                        # if not ((dst, dport, src, sport) in self.tcp.tcp_connections_seen or (
                        #         src, sport, dst, dport) in self.tcp.tcp_connections_seen):
                        #   self.tcp.tcp_connections.append((src, sport, dst, dport, offset, ts - first_ts))
                        self.tcp.tcp_connections.append(ptcp)
                        ##    self.tcp.tcp_connections_seen.add((src, sport, dst, dport))



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
                        pudp["payload"] = self.udp.udp_dissect(connection, udp.data, self.dns)  # Data Octets - Payload

                        # Populate list of UDP Connections, default of Cuckoo sandbox
                        src, sport, dst, dport = (
                            connection["src"], connection["sport"], connection["dst"], connection["dport"])
                        if not ((dst, dport, src, sport) in self.udp.udp_connections_seen or (
                                src, sport, dst, dport) in self.udp.udp_connections_seen):
                            self.udp.udp_connections.append((src, sport, dst, dport, offset, ts - first_ts))
                            self.udp.udp_connections_seen.add((src, sport, dst, dport))

                # if payload of IP is a package ICMP
                elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                    icmp = ip.data
                    if not isinstance(icmp, dpkt.icmp.ICMP):
                        icmp = dpkt.icmp.ICMP(icmp)

                    picmp = self.icmp.icmp_dissect(connection, icmp)  # Populate Dictionary ICMP founded and parsed

                offset = file.tell()
            except AttributeError:
                continue
            except dpkt.dpkt.NeedData:
                continue
            except Exception as e:
                log.exception("Failed to process packet: %s", e)

        file.close()

        # Post processors for reconstructed flows.
        self.smtp.process_smtp()

        # Build results dict.

        self.results["hosts"] = self.ip.unique_hosts
        self.results["domains"] = self.dns.unique_domains
        #self.results["tcp"] = self.tcp.tcp_connections
        self.results["tcp"] = [conn_from_flowtuple(i) for i in self.tcp.tcp_connections]
        self.results["udp"] = [conn_from_flowtuple(i) for i in self.udp.udp_connections]
        self.results["icmp"] = self.icmp.icmp_requests
        self.results["http"] = self.http.http_requests
        self.results["dns"] = self.dns.dns_requests
        self.results["smtp"] = self.smtp.smtp_requests
        self.results["irc"] = self.irc.irc_requests

        #self.results["pcap_parser"] = [self.parser]

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
