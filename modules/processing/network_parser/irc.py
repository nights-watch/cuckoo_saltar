__author__ = 'targaryen'

import cStringIO
import re
from lib.cuckoo.common.irc import ircMessage
from lib.cuckoo.common.utils import convert_to_printable


class Irc:

    def __init__(self):
        self._messages = []
        pass

    @staticmethod
    def check(tcp):
        """
        Checks for IRC traffic.
        Identify
        @param tcpdata: tcp data flow
        """
        if not (tcp.dport != 21):
            print "IRC found"
            return False
        try:
            req = ircMessage()
        except Exception:
            return False

        return req.isthereIRC(tcp.data)

    @staticmethod
    def dissect(irc):
        __methods_client = dict.fromkeys(("PASS", "JOIN", "USER", "OPER", "MODE", "SERVICE", "QUIT", "SQUIT",
            "PART", "TOPIC", "NAMES", "LIST", "INVITE",
            "KICK", "PRIVMSG", "NOTICE", "MOTD", "LUSERS", "VERSION", "STATS", "LINKS", "TIME", "CONNECT",
            "TRACE", "ADMIN", "INFO", "SERVLIST",
            "SQUERY", "WHO", "WHOIS", "WHOWAS", "KILL", "PING", "PONG", "ERROR", "AWAY", "REHASH", "DIE", "RESTART",
            "SUMMON", "USERS", "WALLOPS",
            "USERHOST", "NICK", "ISON"))

        _messages = []
        _sc = {}
        _cc = {}

        try:
            f = cStringIO.StringIO(irc)
            lines = f.readlines()
        except Exception:
            return False

        for element in lines:
            if not re.match("^:", element) is None:
                command = "([a-zA-Z]+|[0-9]{3})"
                params = "(\x20.+)"
                irc_server_msg = re.findall("(^:[\w+.{}!@|()]+\x20)"+command+params,element)
                if irc_server_msg:
                    _sc["prefix"] = convert_to_printable(irc_server_msg[0][0].strip())
                    _sc["command"] = convert_to_printable(irc_server_msg[0][1].strip())
                    _sc["params"] = convert_to_printable(irc_server_msg[0][2].strip())
                    _sc["type"] = "server"
                    _messages.append(dict(_sc))
            else:
                irc_client_msg = re.findall("([a-zA-Z]+\x20)(.+[\x0a\0x0d])",element)
                if irc_client_msg and irc_client_msg[0][0].strip() in __methods_client:
                    _cc["command"] = convert_to_printable(irc_client_msg[0][0].strip())
                    _cc["params"] = convert_to_printable(irc_client_msg[0][1].strip())
                    _cc["type"] = "client"
                    _messages.append(dict(_cc))

        pirc={}
        pirc["layer"] = 7
        pirc["protocol_name"] = "IRC"
        pirc["messages"] = _messages

        return pirc

    @staticmethod
    def _unpack(self, buf):
        """Extract into a list irc messages of a tcp streams.
        @buf: tcp stream data
        """

