__author__ = 'targaryen'

from lib.cuckoo.common.irc import ircMessage


class Irc:

    def __init__(self):
        # List containing all IRC requests.
        self.irc_requests = []

    def check_irc(self, tcpdata):
        """
        Checks for IRC traffic.
        Identify
        @param tcpdata: tcp data flow
        """
        try:
            req = ircMessage()
        except Exception:
            return False

        return req.isthereIRC(tcpdata)

    def add_irc(self, tcpdata):
        """
        RFC 1459 - Internet Relay Chat Protocol - https://tools.ietf.org/html/rfc1459

        Adds an IRC communication.
        @param tcpdata: TCP data in flow
        @param dport: destination port
        """
        pirc={}
        irc_request=[]
        try:
            reqc = ircMessage()
            reqs = ircMessage()
            filters_sc = ["266"]
            self.irc_requests = self.irc_requests + \
                                reqc.getClientMessages(tcpdata) + \
                                reqs.getServerMessagesFilter(tcpdata, filters_sc)
            irc_request=self.irc_requests
        except Exception:
            return "Can't retrieve IRC messages from TCP data"

        return irc_request