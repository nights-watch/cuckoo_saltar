__author__ = 'targaryen'

import json
import urllib2
import socket


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
        winterfellServer = "http://46.101.169.4/"
        listHosts=[]
        for host in hosts:
            try:
                print host
                json_str = urllib2.urlopen(winterfellServer + host, timeout=5).read()
                json_dict = json.loads(json_str)
                listHosts.append(json_dict)
                print host + " DONE"

            except urllib2.URLError, err:
                print host + " " + err.read()
                errdict = {host: err.read()}
                listHosts.append(errdict)
                pass

            except socket.timeout, err:
                errdict = {host: "Socket TimeOut"}
                print errdict
                listHosts.append(errdict)
                pass


        return listHosts


