#!/bin/bash
# ------------------------------------------------------------------
# [Author] Hialo Muniz, Vinicius Franco
#  Description:
#
#		   This script checks if there's any VMs running, checks its
#          status then executes the main script of cuckoo sandbox, with
#		   a list of malwares contained in MALWARES_PATH. This script also 
#		   checks if there is any new signatures in cuckoo's and yara's
#		   repositories.
#
# Dependency:
#     Writing permissions in /opt. Commands:
#          sudo chown $USER:root -R /opt/
#          sudo chmod 755 -R /opt/
#          * * * * * cd /opt/cuckoo_saltar/scripts; export DISPLAY=:0 && nohup ./script.sh &
#     iptables script already executed in the machine, necessary for the 
#     VM network to work.
# ------------------------------------------------------------------

VMNAME="vmMalware"

CUCKOO_PATH=/opt/cuckoo_saltar
CUCKOO_SCRIPT=$CUCKOO_PATH/cuckoo.py
SUBMIT_SCRIPT=$CUCKOO_PATH/utils/submit.py
MALWARE_PATH=$HOME/malwares_folder

LOG_PATH=/opt/logs
LOG_FILE=log.txt
CUCKOO_LOG_FILE=cuckoo_log.txt
PYTHON=python
CUCKOO=cuckoo.py

SERVICE=cuckoo
TIME=$(date +"%T")

##############################################################

function startingVMs(){
	VBoxManage list runningvms | grep $VMNAME > /dev/null 

	if [ $? -ne 0 ]; then
		echo -e $TIME " Non-Active VMs. Running..."
			vboxmanage startvm $VMNAME"1" --type headless #>> $LOG_PATH/$LOGFILE $DATA_STREAM
		#for i in {1..3}
		#do
			#vboxmanage startvm $VMNAME$i --type headless >> $LOG_PATH/$LOGFILE $DATA_STREAM
		#done
	else
		echo -e $TIME " Active VMs."

	fi
}

##############################################################

if [ ! -d $LOG_PATH ]; then
	echo -e $TIME " Log directory doesn't exist. Creating..."
	mkdir $LOG_PATH -m 775
fi

if ps ax | grep -i $CUCKOO | grep -v grep > /dev/null; then
    echo -e $TIME  " $SERVICE service is running already. Exiting...\n"
else
	startingVMs
	$PYTHON $CUCKOO_SCRIPT --clean
	$PYTHON $SUBMIT_SCRIPT $MALWARE_PATH --enforce-timeout
	$PYTHON $CUCKOO_SCRIPT -d >> $LOG_PATH/$CUCKOO_LOG_FILE 2>&1 # variavel para que o cron escreva o stream de dados no log.txt. 1 para STDOUT, 2 para STDERR.
fi




