__author__ = 'targaryen'

import socket
import ipwhois


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
        hosts_lists = {}
        for host in hosts:
            try:
                i = ipwhois.IPWhois(host)
                hosts_lists[host] = i.lookup_rws()
            except Exception, e:
                hosts_lists[host] = "lookup failed"
                print e
                pass

        return hosts_lists


