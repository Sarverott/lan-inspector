#!/usr/bin/python

# part of lan-inspector
# Sett Sarverott
# 2021

from system import netDataCrush as neDaCru
from system import netInquisitor as neInq


#neDaCru.inputsDirClear()


#switch_1=neInq.DlinkTelnetCheck()
#switch_1.setup("127.0.0.1", "admin", "admin")
#switch_1.getDataFromHost()
#switch_1.saveResults()



#switch_2=neInq.DlinkTelnetCheck()
#switch_2.setup("127.0.0.1", "admin", "admin")
#switch_2.getDataFromHost()
#switch_2.saveResults()



gistmaclist=neDaCru.MacListFromGistCheck()
gistmaclist.downloadListFile()
gistmaclist.writeListFiles()
gistmaclist.saveStates()



nmapdata=neDaCru.NmapAnaliser("./input-data/nmap-scan-YYYY-MM-DD.xml")
nmapdata.getRoot()
nmapdata.saveStates()



whitelist=neDaCru.WhitelistAnaliser("./input-data/mac-address-list.csv")
whitelist.saveStates()



netNote=neDaCru.NetworkNotepadAnaliser()
netNote.saveStates()
