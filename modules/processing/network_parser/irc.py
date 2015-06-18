__author__ = 'targaryen'

from lib.cuckoo.common.irc import ircMessage


class Irc:

    def __init__(self):
        pass

    @staticmethod
    def check(tcp):
        """
        Checks for IRC traffic.
        Identify
        @param tcpdata: tcp data flow
        """
        if not (tcp.dport != 21):
            return False
        try:
            req = ircMessage()
        except Exception:
            return False

        return req.isthereIRC(tcp.data)

    @staticmethod
    def dissect(data):
        return {}
