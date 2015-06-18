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
    def dissect(data):
        return {}