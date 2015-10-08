"""
    This module is responsible for processing pcap files into JSON objects,
    persisting them in a MongoDB collection.

    It tries to benefit from parallel processing to make things faster.
"""

# Python modules
import time
import os
import json
from bson.json_util import dumps
from subprocess import check_output
import multiprocessing as mp

# PIP install
import xmltodict
import pymongo

# SALTAR modules
import executioncontrol as ce
import config as cfg

__author__ = "Luciano Moreira"
__credits__ = ["Marcelo xyz", ""]
__copyright__ = "Copyright 2015, SALTAR Project"
__version__ = "0.5"


def print_message(message):
    """ Print messages to the console for debugging purpose

    Args:
        message (str): a message to be printed
    """
    if (cfg.DEBUG_MODE):
        pid = 'PID: ' + str(os.getpid()) + '; '
        print (pid + message + '; Timestamp: '
               + time.strftime("%Y-%m-%d %H:%M:%S"))


def save_pcaplist_to_mongodb(pcaplist, malware_name):
    """ Convert a list to JSON, shred and insert into MongoDB

        The function expects a list with the format defined in the
        pcap_to_list module. This will ensure that the proper break down
        of the document structure is aligned with the expected output.

        The MongoDB database name is pcap and the collection is malware.
        So far this configuration is hardcoded, if needed we should adjust it.

        Args:
            pcaplist (list): list to be converted to JSON
            malware_name (str)
    """
    con = pymongo.MongoClient(cfg.HOST_NAME, cfg.PORT)
    db = con.pcap
    col = db.malware

    print_message('Loading JSON for malware: ' + malware_name)

    # There should be a smarter way of doing this...
    jsonfile = json.loads(json.dumps(pcaplist))

    print_message('Breaking down JSON for malware: ' + malware_name)

    firstLevelCount = 0
    for item in jsonfile:
        firstLevelCount += 1
        secondLevelCount = 0

        # Malware name and sequence number are important to make possible
        # to reorganize data when querying the collection.
        item[u'malware'] = u'' + malware_name
        item[u'seqnum'] = firstLevelCount

        try:
            lengthBson = len(dumps(item))

            # Large elements need a second level break down
            if (lengthBson > 16777200):
                for item_sl in item['proto']:
                    secondLevelCount += 1
                    # print (str(secondLevelCount) +' :'
                    #   +  str(len(dumps(item_sl))))

                    # Recreate the upper element and attributes lost
                    # during level second level break down
                    data = {u'proto': []}
                    data[u'malware'] = u'' + malware_name
                    data[u'seqnum'] = firstLevelCount
                    data[u'childseqnum'] = secondLevelCount
                    data['proto'].append(item_sl)

                    if (cfg.MAKE_SHRED_JSON_FILE):
                        with open('Out_' + malware_name + '_' +
                                  str(firstLevelCount) + '_' +
                                  str(secondLevelCount) + '.txt', 'w') as sa:
                            json.dump(data, sa)

                            print_message(
                                'Wrote second level' +
                                ' output for malware: ' + malware_name)

                    # Insert fragment into the database
                    col.insert_one(data)

            # Second level break down isn't needed
            else:

                if (cfg.MAKE_SHRED_JSON_FILE):
                    with open('Out_' + malware_name + '_'
                              + str(firstLevelCount) + '.txt', 'w') as sa:
                        json.dump(item, sa)

                        print_message(
                            'Wrote first level output ' +
                            'for malware: ' + malware_name)

                # Insert fragment into the database
                col.insert_one(item)

        except Exception as e:
            raise e

    print_message('JSON into MongoDB. Malware: ' + malware_name)


def pcap_to_list(pcap_path, file_name):
    """ Convert a pcap file to a dictionary

        The function converts a pcap file into a XML using tshark tool,
        following the PDML definition for the XML output.

        The XML is converted into a Python dictionary without any
        schema definition or interference. Any change in the format will
        alter the JSON parsing later on.

        Args:
            pcap_path (str): path of the pcap file
            file_name (str): name of the file (with extension)
    """
    os.chdir(pcap_path)

    remove_first_layers = True
    malware_name = os.path.splitext(os.path.splitext(file_name)[0])[0]
    print_message('Malware: ' + malware_name)

    pcap_path = pcap_path + file_name

    # Generate XML file from pcap using tshark feature
    pcacp_xml = check_output(["tshark", "-T", "pdml", "-r", pcap_path])
    print_message('XML from tshark generated: ' + pcap_path)

    # Get a Python dictionary from XML
    pcap_dict = xmltodict.parse(pcacp_xml)
    array = pcap_dict['pdml']['packet']

    if remove_first_layers is True:
        for i in array:
            del i['proto'][0]
            del i['proto'][0]
            del i['proto'][0]

    print_message('Python dict from XML generated: ' + pcap_path)

    if (cfg.MAKE_JSON_FILE):
        with open(pcap_path + malware_name + '.json', 'w') as f:
            json.dump(array, f)
            print_message('JSON output file generated: ' + pcap_path)

    save_pcaplist_to_mongodb(array, malware_name)
    ce.register_pcap_processing(malware_name, 'Success', '')


def main():
    """ Execute child processes assinging files to each one """

    print_message('Start time - main()')
    parallelism = cfg.MAX_CORES
    print_message('parallelism: ' + str(parallelism))

    # pcap_path = cfg.DIR_PCAP + cfg.PCAP_EXTENSION

    # Array to receive child processes
    ps = []
    numPs = 0

    # Change the working directory" to the defined directory
    os.chdir(cfg.DIR_PCAP)

    # Sort files by size, this will improve processing time with a
    # similar processing time between child processes
    arqs = os.listdir()
    sl = sorted(arqs, key=os.path.getsize)

    for ffile in sl:
        if ffile.endswith(cfg.PCAP_EXTENSION):

            malware_name = os.path.splitext(os.path.splitext(ffile)[0])[0]
            # If already processed, do nothing
            if ce.malware_processed(malware_name):
                print_message('Malware ' + malware_name + ' already processed')
                continue

            # Arquivos > 15MB, parallelism = 4
            # Arquivos > 20MB, parallelism = 2
            # Arquivos > 25MB, parallelism = 1
            if ((os.path.getsize(ffile) > 15728640)
                    and (parallelism > cfg.MODERATED_CORES)):

                parallelism = cfg.MODERATED_CORES
                print_message('Parallelism: ' + str(parallelism))

            if ((os.path.getsize(ffile) > 20971520)
                    and (parallelism > cfg.LOW_CORES)):

                parallelism = cfg.LOW_CORES
                print_message('Parallelism: ' + str(parallelism))

            if ((os.path.getsize(ffile) > 26214400)
                    and (parallelism > 1)):

                parallelism = 1
                print_message('Parallelism: ' + str(parallelism))

            # Add child process to be executed
            p = mp.Process(target=pcap_to_list, args=(cfg.DIR_PCAP, ffile))
            ps.append(p)
            numPs += 1

        # If current degree of parallelism is reached, execute all.
        if (numPs >= parallelism):

            for p in ps:
                p.start()

            for p in ps:
                p.join()

            # Restart all data structures to receive new processes
            ps = []
            numPs = 0

    # Before quitting, process any residual file in the array
    for p in ps:
        p.start()

    for p in ps:
        p.join()

    print_message('End time - main()')


if __name__ == '__main__':
    main()
