__author__ = 'targaryen'

import logging
import os
import sys
import json
from network_parser_independent import ip as ipparser

try:
    import dpkt
    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Parser:

    def __init__(self, filepath):
        self.filepath = filepath
        pass

    def parse(self):
        log = logging.getLogger("Processing.Pcap")
        result = {}
        pcap = self.readPcap()

        if pcap is None:
            return {}
        pcapLine = 0

        for ts, buf in pcap:
            pcapLine += 1
            ippars = ipparser.Ip()
            try:
                _ip = iplayer_from_raw(buf, pcap.datalink())
                if ippars.checkv4(_ip) or ippars.checkv6(_ip):  # RFC 791
                    result[pcapLine] = ippars.dissect(_ip)
                else:
                    result[pcapLine] = "unknown protocol on layer 3"
                    continue
            except AttributeError:
                continue
            except dpkt.dpkt.NeedData:
                continue
            except Exception as e:
                log.exception("Failed to process packet: %s", e)

        return result

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
            file = open(self.filepath, "rb")
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
        print("Houston we've got a problem")#raise CuckooProcessingError("unknown PCAP linktype")
    return ip

if __name__ == '__main__':
    if sys.argv[1] == '--help':
        print "arg1 - path of the pcap \narg2 - path to the json file results"
    else:
        parser = Parser(sys.argv[1])
        filename = os.path.splitext(os.path.basename(sys.argv[1]))[0]
        output = sys.argv[2] if sys.argv[2] is not None else ""
        with open(output + filename + '.json', 'w') as fp:
            json.dump(parser.parse(), fp, indent=2)
