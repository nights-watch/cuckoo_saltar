__author__ = 'targaryen'

class Smtp:

    def __init__(self):
        pass

    @staticmethod
    def check(data):
        if data.dport == 25:
            return True
        return False

    @staticmethod
    def dissect(smtp):
        psmtp={}
        psmtp["layer"] = 7
        psmtp["protocol_name"] = "SMTP"
        psmtp["data"] = smtp

        return psmtp