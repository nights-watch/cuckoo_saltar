__author__ = 'targaryen'

from subprocess import check_output
import xmltodict

class Tshark:

    def __init__(self):
        pass

    def dissect(self, pcap_path):
        pcacp_xml = check_output(["tshark","-T","pdml","-r",pcap_path])

        # pcacp_xml = pcacp_xml.replace("showname=","sn=")
        # pcacp_xml = pcacp_xml.replace("show=","w=")
        # pcacp_xml = pcacp_xml.replace("size=","s=")
        # pcacp_xml = pcacp_xml.replace("name=","n=")
        # pcacp_xml = pcacp_xml.replace("pos=","p=")
        # pcacp_xml = pcacp_xml.replace("value=","v=")
        # pcacp_xml = pcacp_xml.replace("unmaskedvalue=","u=")
        # pcacp_xml = pcacp_xml.replace("hide=","h=")
        # pcacp_xml = pcacp_xml.replace("field=","f=")

        # print pcacp_xml

        pcap_dict = xmltodict.parse(pcacp_xml)
        return pcap_dict


