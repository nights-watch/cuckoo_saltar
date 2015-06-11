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
#     iptables script already executed in the machine, necessary for the 
#     VM network to work.
# ------------------------------------------------------------------

VMNAME="vmMalware"

CUCKOO_PATH=/opt/cuckoo_saltar
CUCKOO_SCRIPT=$CUCKOO_PATH/cuckoo.py
SUBMIT_SCRIPT=$CUCKOO_PATH/utils/submit.py
MALWARE_PATH=$HOME/malwares_folder

LOG_PATH=/opt/logs
LOGFILE=log.txt
PYTHON=python

SERVICE=cuckoo
TIME=$(date +"%T")

GITCUCKOO="gitCuckooCommunity"
GITYARA="gitYaraCommunity"



##############################################################

function startingVMs(){
	VBoxManage list runningvms | grep $VMNAME > /dev/null 

	if [ $? -ne 0 ]; then
		echo -e $TIME " Non-Active VMs. Running..."
			vboxmanage startvm $VMNAME"1" --type vrdp #>> $LOG_PATH/$LOGFILE $DATA_STREAM
		#for i in {1..3}
		#do
			#vboxmanage startvm $VMNAME$i --type headless >> $LOG_PATH/$LOGFILE $DATA_STREAM
		#done
	else
		echo -e $TIME " Active VMs."

	fi
}

##############################################################

function syncCuckooSignatures(){
	CUCKOO_SIG_DIR=/opt/$GITCUCKOO
	CUCKOO_GIT_DIR=$CUCKOO_SIG_DIR/community

	if [ ! -d $CUCKOO_SIG_DIR ]; then
		echo -e $TIME " Cuckoo signatures directory doesn't exist. Creating..."
		mkdir $CUCKOO_SIG_DIR -m 775

		echo -e $TIME " Cloning remote repository..."
		git clone https://github.com/cuckoobox/community.git $CUCKOO_SIG_DIR/community
	fi

	cd $CUCKOO_GIT_DIR

	echo -e $TIME " Updating possible new cuckoo signatures..."
	git pull

	cp -rf $CUCKOO_GIT_DIR/modules/signatures/* /opt/cuckoo_saltar/modules/signatures/
}

##############################################################

function syncYaraSignatures(){
	YARA_SIG_DIR=/opt/$GITYARA

	if [ ! -d $YARA_SIG_DIR ]; then
		echo -e $TIME " YARA signatures directory doesn't exist. Creating..."
		mkdir $YARA_SIG_DIR -m 775

		echo -e $TIME " Cloning remote repository..."
		git clone https://github.com/citizenlab/malware-signatures.git $YARA_SIG_DIR
	fi

	cd $YARA_SIG_DIR

	echo -e $TIME " Updating possible new YARA signatures..."
	git pull

	cp -rf $YARA_SIG_DIR/yara-rules/malware-families $CUCKOO_PATH/data/yara/

	echo -e "include \"/opt/cuckoo_saltar/data/yara/binaries/shellcodes.yar\"" > /opt/cuckoo_saltar/data/yara/index_binaries.yar
	echo -e "include \"/opt/cuckoo_saltar/data/yara/binaries/embedded.yar\"" >> /opt/cuckoo_saltar/data/yara/index_binaries.yar
	echo -e "include \"/opt/cuckoo_saltar/data/yara/binaries/vmdetect.yar\"" >> /opt/cuckoo_saltar/data/yara/index_binaries.yar
	echo -e "include \"/opt/cuckoo_saltar/data/yara/malware-families/\"" >> /opt/cuckoo_saltar/data/yara/index_binaries.yar
}

##############################################################

if [ ! -d $LOG_PATH ]; then
	echo -e $TIME " Log directory doesn't exist. Creating..."
	mkdir $LOG_PATH -m 775
fi

if ps ax | grep -v grep | grep $SERVICE > /dev/null; then
    echo -e $TIME  " $SERVICE service is running already. Exiting...\n"
else
	syncCuckooSignatures
	syncYaraSignatures
	startingVMs
	$PYTHON $CUCKOO_SCRIPT --clean
	$PYTHON $SUBMIT_SCRIPT $MALWARE_PATH --enforce-timeout
	$PYTHON $CUCKOO_SCRIPT -d >> $LOG_PATH/$LOGFILE 2>&1 # variavel para que o cron escreva o stream de dados no log.txt. 1 para STDOUT, 2 para STDERR.
fi




