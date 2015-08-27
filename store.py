import sys
import os
import json
import shutil

TMP_DIR='/opt/tmp'

def process(local, remote):
        entries = [os.path.join(local,f) for f in os.listdir(local) if os.path.isdir(os.path.join(local,f))]
        total = len(entries)
        i = 1
        for entry in entries:
                print 'Processing ',i,' of ',total,' (',(float(i) / total * 100),'%): ', entry
                i += 1
                process_entry(entry, remote)

def process_entry(path, remote_path):
        pcap_file = os.path.join(path, 'dump.pcap')
        report_file = os.path.join(path, 'reports/report.json')

        if not os.path.exists(pcap_file):
                print 'No pcap file. Aborting entry'
                return

        if not os.path.exists(report_file):
                print 'No report file. Aborting entry'
                return
        
        try:
                malware_name = find_name(report_file)
        except:
                print 'Corrupted report file. Aborting entry.'
                return
        
        tmp_pcap_file = gen_pcap(pcap_file, malware_name)
        
        if(os.path.exists(os.path.join(remote_path, tmp_pcap_file[len(TMP_DIR)+1:]))):
                print 'Skipping entry. Already in remote'
                delete(tmp_pcap_file)
                return

        tmp_hash_file = gen_hash(tmp_pcap_file)

        push(tmp_pcap_file, remote_path)
        push(tmp_hash_file, remote_path)

        delete(tmp_pcap_file)
        delete(tmp_hash_file)

def find_name(path):
        tmp = open(path)
        data = json.load(tmp)
        tmp.close()
        return data['target']['file']['name']

def gen_hash(path):
        base_path = path[:len(TMP_DIR)]
        target_file = path[len(TMP_DIR)+1:]
        sha1_file = base_path + '/' + target_file + '.sha1'
        os.chdir(TMP_DIR)
        os.system('sha1sum -b ' + target_file + ' > ' + sha1_file)
        return sha1_file

def gen_pcap(path, name):
        pcap_name = name + ".pcap"
        target = TMP_DIR + "/" + pcap_name
        shutil.copy2(path, target)
        return target

def push(path,target):
        shutil.copy2(path, target)

def delete(path):
        os.remove(path)

if __name__ == '__main__':
        remote_path = sys.argv[1]
        local_path = sys.argv[2]
        tmp_path = sys.argv[3]

        if not os.path.exists(tmp_path):
                os.makedirs(tmp_path)
        
        TMP_DIR = tmp_path

        process(local_path, remote_path)
