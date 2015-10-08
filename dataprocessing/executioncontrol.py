"""
    This module is responsible for storing and retrieving processing
    information from the MongoDB database.

    Control databases used:
        - pcaptojson: for importing pcap data into MongoDB
        - jsonextract: for extracting data from JSON (stored in MongoDB)
"""

# Python modules
import time
# PIP install
import pymongo
# Import config definitions
import config as cfg

__author__ = "Luciano Moreira"
__credits__ = ["Marcelo xyz", ""]
__copyright__ = "Copyright 2015, SALTAR Project"
__version__ = "0.5"

# Global variables
con = pymongo.MongoClient(cfg.HOST_NAME, cfg.PORT)
db = con.controleExecucao


def malware_processed(malware_name):
    col = db.pcaptojson
    resultset = col.find({'malware': malware_name})

    # Verify if there is any element with the Success state
    if (resultset.count() == 0):
        return False
    else:
        for control in resultset:
            if (control['status'] == 'Success'):
                return True

    # If there isn't any Success element, returns False
    # This makes an invalid state also a False return
    return False


def json_processed(malware_name):
    col = db.jsonextract
    resultset = col.find({'malware': malware_name})

    # Verify if there is any element with the Success state
    if (resultset.count() == 0):
        return False
    else:
        for control in resultset:
            if (control['status'] == 'Success'):
                return True

    # If there isn't any Success element, returns False
    # This makes an invalid state also a False return
    return False


def register_pcap_processing(malware_name, status, reason):
    col = db.pcaptojson
    myjson = {'malware': malware_name, 'status': status}
    myjson['timestamp'] = time.strftime("%Y-%m-%d %H:%M:%S")
    if (reason != ""):
        myjson['reason'] = reason
    col.insert_one(myjson)


def register_json_extract(malware_name, status):
    col = db.jsonextract
    myjson = {'malware': malware_name, 'status': status}
    myjson['timestamp'] = time.strftime("%Y-%m-%d %H:%M:%S")
    col.insert_one(myjson)
