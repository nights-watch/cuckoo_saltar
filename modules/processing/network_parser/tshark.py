__author__ = 'targaryen'

from subprocess import check_output
import xmltodict

class Tshark:

    def __init__(self):
        pass

    def dissect(self, pcap_path):
        pcacp_xml = check_output(["tshark","-T","pdml","-r",pcap_path])
        pcap_dict = xmltodict.parse(pcacp_xml)
        return pcap_dict


