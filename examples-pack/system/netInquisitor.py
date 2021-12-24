#!/usr/bin/python

# part of lan-inspector
# Sett Sarverott
# 2021

from system import fileReaders as fiRe
from system import statisticData as staDa


from telnetlib import Telnet


import time


def standardArchivesCheck(archivename):
    fiRe.safeMkdir("./archives")
    fiRe.safeMkdir("./archives/" + archivename)
    fiRe.safeMkdir("./archives/" + archivename + "/_unknown_macs_")
    fiRe.safeMkdir("./archives/" + archivename + "/#INPUTS")


class DlinkTelnetCheck:
    def __init__(self):
        print("prepared for DGS-1210-48")

    def setup(self, host, user, password):
        self.host=host
        self.user=user
        self.password=password

    def saveResults(self, archivename="mydefaultnetwork"):
        standardArchivesCheck(archivename)
        filename = self.host.replace(".", "_") + "-telnet-" + staDa.getTimestamp() + ".log"
        with open("./archives/" + archivename + "/#INPUTS/" + filename, "w") as dumpLog:
            dumpLog.write(self.rawDebugInfo)
            dumpLog.close()

    def getDataFromHost(self):
        tn = Telnet(self.host)
        tn.read_until(b"login: ")
        tn.write(self.user.encode('ascii') + b"\n")
        if self.password:
            tn.read_until(b"Password: ")
            tn.write(self.password.encode('ascii') + b"\n")

        tn.write(b"show switch\n")
        time.sleep(0.1)
        tn.write(b"debug info\n")
        for i in range(100):
            time.sleep(0.1)
            tn.write(b" ")
        #tn.close()
        time.sleep(0.1)
        self.rawDebugInfo=tn.read_very_eager().decode('ascii')
        tn.close()
