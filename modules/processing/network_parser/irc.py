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
            print "IRC found"
            return False
        try:
            req = ircMessage()
        except Exception:
            return False

        return req.isthereIRC(tcp.data)

    @staticmethod
    def dissect(irc):
        req = ircMessage()
        req.isthereIRC(irc)

        pirc={}
        pirc["layer"] = 7
        pirc["protocol_name"] = "IRC"
        pirc["data"] = irc

        return pirc

    def _unpack(self, buf):
        """Extract into a list irc messages of a tcp streams.
        @buf: tcp stream data
        """
        try:
            f = cStringIO.StringIO(buf)
            lines = f.readlines()
        except Exception:
            log.error("Failed reading tcp stream buffer")
            return False

        for element in lines:
            if not re.match("^:", element) is None:
                command = "([a-zA-Z]+|[0-9]{3})"
                params = "(\x20.+)"
                irc_server_msg = re.findall("(^:[\w+.{}!@|()]+\x20)"+command+params,element)
                if irc_server_msg:
                    self._sc["prefix"] = convert_to_printable(irc_server_msg[0][0].strip())
                    self._sc["command"] = convert_to_printable(irc_server_msg[0][1].strip())
                    self._sc["params"] = convert_to_printable(irc_server_msg[0][2].strip())
                    self._sc["type"] = "server"
                    self._messages.append(dict(self._sc))
            else:
                irc_client_msg = re.findall("([a-zA-Z]+\x20)(.+[\x0a\0x0d])",element)
                if irc_client_msg and irc_client_msg[0][0].strip() in self.__methods_client:
                    self._cc["command"] = convert_to_printable(irc_client_msg[0][0].strip())
                    self._cc["params"] = convert_to_printable(irc_client_msg[0][1].strip())
                    self._cc["type"] = "client"
                    self._messages.append(dict(self._cc))
