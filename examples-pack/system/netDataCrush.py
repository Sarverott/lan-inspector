#!/usr/bin/python

# part of lan-inspector
# Sett Sarverott
# 2021

import xml.etree.ElementTree as ET
from xml.dom import minidom
import csv
import hashlib
import json
import base64
import os
import urllib.request
import codecs

from system import statisticData as staDa
from system import fileReaders as fiRe

#class NetworkNotepadAnaliser:
#    def __init__(csvfilepath):
#        self.path=csvfilepath

from github import Github

github_scout_hook=Github()

def inputsDirClear(archivename="mydefaultnetwork"):
    fiRe.clearDir("./archives/" + archivename + "/#INPUTS")

def standardArchivesCheck(archivename="mydefaultnetwork"):
    fiRe.safeMkdir("./archives")
    fiRe.safeMkdir("./archives/" + archivename)
    fiRe.safeMkdir("./archives/" + archivename + "/_unknown_macs_")
    fiRe.safeMkdir("./archives/" + archivename + "/#INPUTS")

def parseXmlToDict(element):
    response = []

    for child in list(element):
        if len(list(child)) > 0:
            response.append({
                "name":child.tag,
                "children": parseXmlToDict(child),
                "attrib": child.attrib
            })
        else:
            response.append({
                "name":child.tag,
                "text": child.text or '',
                "attrib": child.attrib
            })
    return response

class MacListFromGistCheck:
    def __init__(self):
        global github_scout_hook
        self.githubHook=github_scout_hook
        self.gistId="b4bb86db86079509e6159810ae9bd3e4"
        self.filename="mac-vendor.txt"
        print("github gistID: "+self.gistId+" filename: "+self.filename)

    def downloadListFile(self):
        self.gist=self.githubHook.get_gist(id=self.gistId)
        self.rawdataType=self.gist.files[self.filename].type
        self.rawdataSize=self.gist.files[self.filename].size
        self.rawdata=self.gist.files[self.filename].content
        self.gistowner=self.gist.owner.login
        self.rawurl=self.gist.files[self.filename].raw_url
        print(self.rawurl)
        print('size='+str(self.rawdataSize)+" type="+self.rawdataType)
        self.getDict()

    def writeListFiles(self, archivename="mydefaultnetwork"):
        standardArchivesCheck(archivename)
        output={
            "mac-map":self.macMap,
            "gist-owner":self.gistowner,
            "gist-id":self.gistId,
            "orginal-filename":self.filename,
            "url":self.rawurl,
            "md5":base64.b64encode(
                hashlib.md5(
                    str.encode(
                        self.rawdata
                    )
                ).digest()
            ).decode(),
            "size":self.rawdataSize
        }
        stampForFile=staDa.getTimestamp()
        with open("./archives/" + archivename + "/gistmaclist-" + stampForFile + ".json", "w") as gistfile:
            gistfile.write(json.dumps(output))
            gistfile.close()
        with codecs.open("./archives/" + archivename + "/#INPUTS/rawgistmaclist-" + stampForFile + ".txt", "w", "utf-8") as gistfile:
            gistfile.write(self.rawdata)
            gistfile.close()

    def readJsonDict(self, dictJson):
        dictJson=json.loads(dictJson)
        self.macMap=dictJson["mac-map"]
        self.gistowner=dictJson["gist-owner"]
        self.gistId=dictJson["gist-id"]
        self.filename=dictJson["orginal-filename"]
        self.rawurl=dictJson["url"]
        self.rawdataSize=dictJson["size"]


    def readLatestListFile(self, archivename="mydefaultnetwork"):
        standardArchivesCheck(archivename)
        inputsDir=os.listdir("./archives/" + archivename + "/#INPUTS")
        oldest=False
        for i in inputsDir:
            if i[:15]=="rawgistmaclist-" and i[-4:]==".txt":
                if oldest:
                    if int(i[12:-5]) > int(oldest[12:-5]):
                        oldest=i
                else:
                    oldest=i
        if oldest:
            with open("./archives/" + archivename + "/#INPUTS/" + oldest) as gistFile:
                self.rawdata=gistFile.read()
                gistFile.close()
            self.getDict()
        else:
            print("gist mac address list file not exists!")


    def readLatestJsonListFile(self, archivename="mydefaultnetwork"):
        standardArchivesCheck(archivename)
        inputsDir=os.listdir("./archives/" + archivename)
        oldest=False
        for i in inputsDir:
            if i[:12]=="gistmaclist-" and i[-5:]==".json":
                if oldest:
                    if int(i[12:-5]) > int(oldest[12:-5]):
                        oldest=i
                else:
                    oldest=i
        if oldest:
            with open("./archives/" + archivename + "/" + oldest) as gistFile:
                self.readJsonDict(gistFile.read())
                gistFile.close()
        else:
            print("gist mac address list file not exists!")


    def getDict(self):
        macvendorsByGist=self.rawdata.split("\n")
        self.macMap={}
        for i in macvendorsByGist:
            tmpMacLine=i.split("\t")
            tmpMac=tmpMacLine[0]
            self.macMap[
                tmpMac[0:2]
                +"-"+
                tmpMac[2:4]
                +"-"+
                tmpMac[4:6]
            ]=tmpMacLine[1:]

    def saveStates(self, archivename="mydefaultnetwork"):
        standardArchivesCheck(archivename)
        hostlist=os.listdir("./archives/" + archivename)
        for i in hostlist:
            if os.path.isdir("./archives/" + archivename + "/" + i) and i[0]!="#" and i[0]!="_":
                if i[:8] in self.macMap:
                    with open("./archives/" + archivename + "/" + i + "/gist-mac-info.json", "w") as gistInfo:
                        gistInfo.write(
                            json.dumps(
                                {
                                    "start-mac":i[:8],
                                    "vendor-info":self.macMap[i[:8]]
                                }
                            )
                        )
                        gistInfo.close()



class OUIMacAddressListCheck:
    def __init__(self):
        self.url="http://standards-oui.ieee.org/oui/oui.txt"
        print("download from "+self.url)

    def downloadList(self, archivename="mydefaultnetwork"):
        urllib.request.urlretrieve(self.url, "./archives/" + archivename + "/#INPUTS/oui-" + staDa.getTimestamp() + ".txt")

    def saveStates(self, archivename="mydefaultnetwork"):
        None

    def readLatestOui(self, archivename="mydefaultnetwork"):
        inputsDir=os.listdir("./archives/" + archivename + "/#INPUTS")
        oldest=False
        for i in inputsDir:
            if i[:4]=="oui-" and i[-4:]==".txt":
                if oldest:
                    if int(i[4:-4]) > int(oldest[4:-4]):
                        oldest=i
                else:
                    oldest=i
        if oldest:
            with open("./archives/" + archivename + "/#INPUTS/" + oldest) as ouiFile:
                self.rawdata=ouiFile.read()
                ouiFile.close()
        else:
            print("OUI mac address list file not exists!")


class NetworkNotepadAnaliser:
    def __init__(self, pathOverload=os.getcwd()):
        self.paths=[]
        self.pathOverload=pathOverload
        self.mainMenuSetupInit()

    def insertFiles(self, *files):
        self.maps=files

    def defaultMachine(self):
        return {
            "whitelist":"nie wystepuje na liscie kart sieciowych",
            "scan-details":"nie wykryto podczas skanowania",
            "extra-description":"brak opisu",
            "captured-packages":"nie przechwycono zadnych pakietow"
        }

    def defaultMapFileDescription(self):
        return {
            "path":self.pathOverload,
            "label":"<BRAK-OPISU>",
            "filename":"plik.ndg"
        }

    def defaultHostFileDescription(self):
        return {
            "path":self.pathOverload,
            "hostname":"<BRAK-OPISU>"
        }

    def readTemplates(self):
        self.hostTemplate=""
        self.menuTemplate=""
        with open("./system/resources/network-notepad-info-sheet/template.ndg") as templatefile:
            self.hostTemplate=templatefile.read()
            templatefile.close()
        with open("./system/resources/network-notepad-info-sheet/main-menu.ndg") as templatefile:
            self.menuTemplate=templatefile.read()
            templatefile.close()

    def inputExampleLines(self):
        return {
            "map-object":' object 4 Ts1 154 248 8 "Donec placerat sapien vitae nunc fermentum feugiat." A:\\path\\to\\main\\location\\of\\network\\prospect\\file.ndg 0 9 1 1 2 128 0 0 false 37 43 false 0 ! !',
            "host-object":' object 5 Host 76 392 6 "Donec placerat sapien vitae nunc fermentum feugiat." A:\\path\\to\\main\\location\\of\\network\\prospect\\file.ndg 0 7 0.5 0.5 2 128 0 0 false 42 33 false 0 ! !',
            "host-label-down":' label 6 s 23 00-00-00-00-00-00 ! ! ! ! true ! &hFF0000& 5 object ! ! 0 255 0 0 !',
            "host-label-up":' label 7 n -16.5 ! ! ! ! ! false ! &h0& 5 ip ! ! 0 255 0 0 !',
            "map-label-down":' label 8 s 28 "Lorem ipsum dolor sit amet, consectetur adipiscing elit." ! ! ! ! true ! &hFF0000& 4 object ! ! 0 255 0 0 !',
            "map-label-up":' label 9 n -28 "Fusce nec aliquam purus, sit amet fermentum enim." ! ! ! ! false ! &h0& 4 ip ! ! 0 255 0 0 !'
        }

    def mainMenuSetupInit(self):
        self.mainMenuSetup={
            "object-index":4,
            "label-index":6,
            "host-origin-y":392,
            "host-origin-x":60,
            "host-x-alteration":76,
            "host-y-alteration":60,
            "host-row-limit":19,
            "host-count":0,
            "map-count":0,
            "map-origin-x":154,
            "map-x-alteration":154
        }

    def generateMapIcons(self, mapDescription):
        tmpTemp=self.inputExampleLines()
        tmpIcon=tmpTemp["map-object"]
        tmpLabelDown=tmpTemp["map-label-down"]
        tmpLabelUp=tmpTemp["map-label-up"]

        tmpIcon=tmpIcon.replace(' 8 "Donec', ' '+str(self.mainMenuSetup['label-index'])+'  "Donec')
        tmpIcon=tmpIcon.replace('Ts1 154 248', 'Ts1 '+str(self.mainMenuSetup['map-origin-x']+(self.mainMenuSetup['map-x-alteration']*self.mainMenuSetup['map-count']))+' 248')
        tmpIcon=tmpIcon.replace("object 4 Ts1", "object "+str(self.mainMenuSetup['object-index'])+" Ts1")

        tmpLabelDown=tmpLabelDown.replace('&hFF0000& 4 object', '&hFF0000& '+str(self.mainMenuSetup['object-index'])+' object')
        tmpLabelDown=tmpLabelDown.replace("label 8 s 28", "label "+str(self.mainMenuSetup['label-index'])+" s 28")
        tmpLabelDown=tmpLabelDown.replace('"Lorem ipsum dolor sit amet, consectetur adipiscing elit."', '"'+mapDescription["filename"]+'"')

        self.mainMenuSetup['label-index']+=1

        tmpIcon=tmpIcon.replace("file.ndg 0 9 1", "file.ndg 0 "+str(self.mainMenuSetup['label-index'])+" 1")

        tmpLabelUp=tmpLabelUp.replace('&h0& 4 ip', '&h0& '+str(self.mainMenuSetup['object-index'])+' ip')
        tmpLabelUp=tmpLabelUp.replace("label 9 n -28", "label "+str(self.mainMenuSetup['label-index'])+" n -28")
        tmpLabelUp=tmpLabelUp.replace('"Fusce nec aliquam purus, sit amet fermentum enim."', '"'+mapDescription["label"]+'"')

        tmpIcon=tmpIcon.replace("Donec placerat sapien vitae nunc fermentum feugiat.", mapDescription["path"])
        tmpIcon=tmpIcon.replace("A:\\path\\to\\main\\location\\of\\network\\prospect\\file.ndg", '"'+mapDescription["path"]+'"')

        self.mainMenuSetup['label-index']+=1
        self.mainMenuSetup['object-index']+=1
        self.mainMenuSetup['map-count']+=1

        return {
            "object":tmpIcon,
            "label-up":tmpLabelUp,
            "label-down":tmpLabelDown
        }

    def generateHostIcons(self, hostDescription):
        tmpTemp=self.inputExampleLines()
        tmpIcon=tmpTemp["host-object"]
        tmpLabelDown=tmpTemp["host-label-down"]
        tmpLabelUp=tmpTemp["host-label-up"]

        tmpIcon=tmpIcon.replace('392 6 ! A:\\path', '392 '+str(self.mainMenuSetup['label-index'])+' ! A:\\path')
        tmpIcon=tmpIcon.replace(
            'object 5 Host 76 392',
            'object 5 Host '+
            str(
                self.mainMenuSetup['host-origin-x']
                +
                (
                    self.mainMenuSetup['host-x-alteration']
                    *
                    (
                        self.mainMenuSetup['host-count']
                        %
                        self.mainMenuSetup['host-row-limit']
                    )
                )
            )+
            ' '+
            str(
                self.mainMenuSetup['host-origin-y']
                +
                self.mainMenuSetup['host-count']%2*10
                +
                (
                    self.mainMenuSetup['host-y-alteration']
                    *
                    (
                        self.mainMenuSetup['host-count']
                        //
                        self.mainMenuSetup['host-row-limit']
                    )
                )
            )
        )
        tmpIcon=tmpIcon.replace("object 5 Host", "object "+str(self.mainMenuSetup['object-index'])+" Host")

        tmpLabelDown=tmpLabelDown.replace('&hFF0000& 5 object', '&hFF0000& '+str(self.mainMenuSetup['object-index'])+' object')
        tmpLabelDown=tmpLabelDown.replace("label 6 s 23", "label "+str(self.mainMenuSetup['label-index'])+" s 23")
        tmpLabelDown=tmpLabelDown.replace('00-00-00-00-00-00', '"'+hostDescription["hostname"]+'"')

        self.mainMenuSetup['label-index']+=1

        tmpIcon=tmpIcon.replace("file.ndg 0 7 0.5 0.5", "file.ndg 0 "+str(self.mainMenuSetup['label-index'])+" 0.5 0.5")

        tmpLabelUp=tmpLabelUp.replace('&h0& 5 ip', '&h0& '+str(self.mainMenuSetup['object-index'])+' ip')
        tmpLabelUp=tmpLabelUp.replace("label 7 n -16.5", "label "+str(self.mainMenuSetup['label-index'])+" n -16.5")

        tmpIcon=tmpIcon.replace("Donec placerat sapien vitae nunc fermentum feugiat.", hostDescription["path"])
        tmpIcon=tmpIcon.replace("A:\\path\\to\\main\\location\\of\\network\\prospect\\file.ndg", '"'+hostDescription["path"]+'"')

        self.mainMenuSetup['label-index']+=1
        self.mainMenuSetup['object-index']+=1
        self.mainMenuSetup['host-count']+=1

        return {
            "object":tmpIcon,
            "label-up":tmpLabelUp,
            "label-down":tmpLabelDown
        }


    def createMachineObject(self, macaddr, mainScopePath, machineInfo, archivename = "mydefaultnetwork"):
        template=self.hostTemplate
        template=template.replace("A:\\path\\to\\main\\location\\of\\network\\prospect\\file.ndg", '"'+mainScopePath+'"')
        template=template.replace("Lorem ipsum dolor sit amet, consectetur adipiscing elit.", machineInfo["whitelist"].replace("\n", "<<crlf>>").replace("\r","").replace('"', "'"))
        template=template.replace("Fusce nec aliquam purus, sit amet fermentum enim.", machineInfo["scan-details"].replace("\n", "<<crlf>>").replace("\r","").replace('"', "'"))
        template=template.replace("Donec placerat sapien vitae nunc fermentum feugiat.", machineInfo["extra-description"].replace("\n", "<<crlf>>").replace("\r","").replace('"', "'"))
        template=template.replace("Sed ullamcorper urna ut nibh elementum, ut commodo risus venenatis.", machineInfo["captured-packages"].replace("\n", "<<crlf>>").replace("\r","").replace('"', "'"))
        hostdatapath="./archives/" + archivename
        hostdatapath+="/" + macaddr + "/net-note.ndg"
        with open(hostdatapath, "w") as templatefile:
            templatefile.write(template)
            templatefile.close()
        return hostdatapath

    def saveStates(self, archivename = "mydefaultnetwork"):
        standardArchivesCheck(archivename)
        archivepath="./archives/" + archivename
        archiveContent=os.listdir(archivepath)
        self.readTemplates()
        self.hosts=[]
        for i in archiveContent:
            if os.path.isdir(archivepath+"/"+i) and i[0]!="#" and i[0]!="_":
                tmphost=self.defaultHostFileDescription()
                tmphost["hostname"]=i
                profileinfo=self.defaultMachine()
                profiledir=os.listdir(archivepath+"/"+i)
                if "whitelisted.json" in profiledir:
                    with open(archivepath+"/"+i+"/"+"whitelisted.json") as whitelistfile:
                        profileinfo["whitelist"]=whitelistfile.read()
                        whitelistfile.close()
                    tmphost["hostname"]=json.loads(profileinfo["whitelist"])["Nazwa komputera"]
                if "gist-mac-info.json" in profiledir:
                    with open(archivepath+"/"+i+"/"+"gist-mac-info.json") as macinfo:
                        profileinfo["whitelist"]+="\n"+macinfo.read()
                        macinfo.close()
                nmapOldestFile=False
                for j in profiledir:
                    if j[:5]=="nmap-":
                        if nmapOldestFile:
                            scanSecondsCurrent=int(j.split("-")[1].split(".")[0])
                            scanSecondsSaved=int(nmapOldestFile.split("-")[1].split(".")[0])
                        else:
                            nmapOldestFile=j
                if nmapOldestFile:
                    tmpscandetails=[]
                    with open(archivepath+"/"+i+"/"+nmapOldestFile) as nmapfile:
                        tmpscandetails=json.loads(nmapfile.read())
                        nmapfile.close()
                tmphost["path"]=(
                    os.getcwd()
                    +
                    self.createMachineObject(
                        i,
                        os.getcwd()+archivepath.replace("/","\\")[1:]+"\\main-prospect.ndg",
                        profileinfo
                    )[1:].replace("/","\\")
                )
                self.hosts.append(tmphost)
        labels=[]
        objects=[]
        for i in self.hosts:
            tmpHost=self.generateHostIcons(i)
            labels.append(tmpHost["label-up"])
            labels.append(tmpHost["label-down"])
            objects.append(tmpHost["object"])

        #

        tmpMain=self.menuTemplate
        tmpMain=tmpMain.replace("lista wszystkich maszyn (0)", "lista wszystkich maszyn ("+str(self.mainMenuSetup['host-count'])+")")
        tmpMain=tmpMain.replace(
            ' object 4 Ts1 154 248 8 "Donec placerat sapien vitae nunc fermentum feugiat." A:\\path\\to\\main\\location\\of\\network\\prospect\\file.ndg 0 9 1 1 2 128 0 0 false 37 43 false 0 ! !',
            "\n".join(objects)
        )
        tmpMain=tmpMain.replace(
            ' label 6 s 23 00-00-00-00-00-00 ! ! ! ! true ! &hFF0000& 5 object ! ! 0 255 0 0 !',
            "\n".join(labels)
        )
        with open(archivepath+"/main-prospect.ndg", "w") as prospectfile:
            prospectfile.write(tmpMain)
            prospectfile.close()

class SwitchLogsAnaliser:
    def __init__(self):
        self.paths=[]

    def addFile(self, path):
        self.paths.append(path)

    def read(self):
        for i in self.paths:
            os.path.basepath(i)

    def removePauses(self):
        for i in self.rawdata:
            self.rawdata[i]=self.rawdata[i].replace("\r\u001b[K\r--More--\u001b[K\u001b\r                \r\u001b[K", "")

class WhitelistAnaliser:
    def __init__(self, csvfilepath):
        self.path=csvfilepath

    def getHosts(self):
        self.hosts=[]
        self.tableHeader=[]
        with open(self.path) as csvfile:
            whitelistraw=list(csv.reader(csvfile, delimiter=';', quotechar='|'))
            whitelistraw.reverse()
            self.tableHeader=whitelistraw.pop()
            whitelistraw.reverse()
            for row in whitelistraw:
                tmphost={}
                for i in range(len(self.tableHeader)):
                    tmphost[self.tableHeader[i]]=row[i]
                self.hosts.append(tmphost)
            csvfile.close()
        return self.hosts

    def saveStates(self, archivename = "mydefaultnetwork"):
        standardArchivesCheck(archivename)
        #print(self.getHosts())
        for i in self.getHosts():
            self.forEachHost(i, archivename)

    def forEachHost(self, host, archivename="mydefaultnetwork"):
        hostdatapath="./archives/" + archivename
        hostdatapath+="/" + host["Adres MAC"]
        fiRe.safeMkdir(hostdatapath)
        with open(hostdatapath+"/whitelisted.json", "w") as whitelist:
            whitelist.write(
                json.dumps(
                    host,
                    sort_keys=False,
                    indent=2
                )
            )
            whitelist.close()


class NmapAnaliser:
    def __init__(self, xmlfilepath):
        self.path=xmlfilepath


    def getRoot(self):
        self.root=ET.parse(self.path).getroot()
        return self.root

    def getNmapScanDetails(self):
        self.scaninfo = {
            "runtag":self.root.attrib,
            "endruntag":self.root.findall("runstats/finished")[0].attrib,
            "results":{
                "hosts":self.root.findall("runstats/hosts")[0].attrib,
                "scansetup":self.root.findall("scaninfo")[0].attrib
            }
        }
        return self.scaninfo

    def getHosts(self):
        self.hosts = self.root.findall('host')
        return self.hosts

    def forEachHost(self, host, archivename="mydefaultnetwork"):
        macaddr = ""
        ip4addr = ""
        ip6addr = ""
        for param in host:
            if param.tag == "address":
                if "addrtype" in param.attrib:
                    if param.attrib["addrtype"] == "mac":
                        macaddr=param.attrib["addr"]

                    elif param.attrib["addrtype"] == "ipv4":
                        ip4addr=param.attrib["addr"]

                    elif param.attrib["addrtype"] == "ipv6":
                        ip6addr=param.attrib["addr"]

        hostdatapath="./archives/" + archivename
        if macaddr != "":
            hostdatapath += "/" + "-".join(macaddr.split(":"))

        elif ip4addr != "":
            hostdatapath += "/_unknown_macs_/" + "_".join(ip4addr.split("."))

        elif ip6addr != "":
            hostdatapath += "/_unknown_macs_/" + "_".join(ip6addr.split(":"))

        else:
            hosthash = hashlib.sha1(
                str.encode(
                    json.dumps(
                        parseXmlToDict(
                            root.findall('host')[0]
                        ),
                        sort_keys=True,
                        indent=4
                    )
                )
            )
            hostdatapath += "/_unknown_macs_/" + base64.b64encode(hosthash.digest()).decode()

        fiRe.safeMkdir(hostdatapath)
        with open(hostdatapath+"/nmap-"+self.scaninfo["runtag"]["start"]+".json", "w") as nmapRaport:
            nmapRaport.write(
                json.dumps(
                    parseXmlToDict(
                        host
                    ),
                    sort_keys=True,
                    indent=4
                )
            )
            nmapRaport.close()

    def saveStates(self, archivename = "mydefaultnetwork"):
        standardArchivesCheck(archivename)
        with open("./archives/" + archivename + "/nmap-scaninfo-"+self.getNmapScanDetails()["runtag"]["start"]+".json", "w") as nmapRaport:
            nmapRaport.write(
                json.dumps(
                    self.scaninfo,
                    sort_keys=True,
                    indent=4
                )
            )
            nmapRaport.close()
        for i in self.getHosts():
            self.forEachHost(i, archivename)
