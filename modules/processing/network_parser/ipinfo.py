__author__ = 'targaryen'

from ipwhois import IPWhois
import json
import urllib2


class Ipinfo:
    """
        Verify the informations about IP presents on list of unique hosts of Cuckoo Sandbox in service WhoIs
    """
    def __init__(self):
        pass

    def info(self, hosts):
        """
        Get info about the IP

        :param hosts: list of hosts to verification
        :return: list of hosts with detailed information
        """
        winterfellServer = "46.101.169.4/"
        listHosts=[]
        for host in hosts:
            json_str = urllib2.urlopen(winterfellServer + host).read()
            json_dict = json.loads(json_str)
            listHosts.append(json_dict)

        return listHosts


