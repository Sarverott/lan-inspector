#!/usr/bin/python

# part of Hermes-raports v1.5.0 (statistic-data)
# Sett Sarverott
# 2020

import json
import datetime
import platform
import os
import urllib.parse
import base64
import codecs
import time


#https://stackoverflow.com/a/27527728
def slashescape(err):
    """ codecs error handler. err is UnicodeDecode instance. return
    a tuple with a replacement for the unencodable part of the input
    and a position where encoding should continue"""
    #print(err, dir(err), err.start, err.end)
    thebyte = err.object[err.start:err.end]
    repl=u''
    for i in thebyte:#Sett MODED
        repl=repl+u'\\x'+hex(ord(chr(i)))[2:]#Sett MODED
    return (repl, err.end)

codecs.register_error('slashescape', slashescape)
#https://stackoverflow.com/a/27527728

mode="debug"


months={
    "Jan":"01",
    "Feb":"02",
    "Mar":"03",
    "Apr":"04",
    "May":"05",
    "Jun":"06",
    "Jul":"07",
    "Aug":"08",
    "Sep":"09",
    "Oct":"10",
    "Nov":"11",
    "Dec":"12"
}

def echo(info):
    if mode[-5:]=="debug":
        print(getToday()+"~~  "+info)
    else:
        None

def emailEncodingDisarm(content, mode, encoding):
    if mode in ("Q", "q"):
        return urllib.parse.unquote(content.replace("=","%")).replace("_", " ")
    elif mode in ("b", "B"):
        return base64.b64decode(content).decode(encoding, "slashescape")
        #return content
    else:
        raise Exception([content, mode, encoding])

def titleDecode(inputData):
    outputData=""
    crypted={
        "encoding":"",
        "mode":"",
        "content":""
    }
    while inputData!="":
        startFlag=inputData.find("=?")
        endEncoding=inputData.find("?", startFlag+2)
        startContent=inputData.find("?", endEncoding+1)
        endContent=inputData.find("?=", startContent+1)
        if startFlag==-1:
            outputData=outputData+inputData
            break
        outputData=outputData+inputData[:startFlag]
        crypted["encoding"]=inputData[startFlag+2:endEncoding]
        crypted["mode"]=inputData[endEncoding+1:startContent]
        crypted["content"]=inputData[startContent+1:endContent]
        inputData=emailEncodingDisarm(crypted["content"], crypted["mode"], crypted["encoding"])+inputData[endContent+2:]

    return outputData

def dateNormalizer(datestring):
    matrix=datestring.split()
    if matrix[0][-1:]=="," and matrix[0][:-1] in (
        "Mon",
        "Tue",
        "Wed",
        "Thu",
        "Fri",
        "Sat",
        "Sun"
    ):
        matrix.pop();

def includeYearShift(lines):
    months=[]
    for i in lines:
        if not i[1] in months:
            months.append(i[1])
    if "01" in months and "12" in months:
        for i in lines:
            if i[1]=="12":
                i[0]=str(int(i[0])-1)

def logDateOptimalization(logDate, forced_year):
    global months
    logDate=logDate.split()
    if len(logDate[1])<2:
        logDate[1]="0"+logDate[1]
    logDate[0]=months[logDate[0]]
    logDate.reverse()
    logDate.append(forced_year)
    logDate.reverse()
    return logDate

def getTimestamp():
    return str(round(time.time()*1000))

def getToday():
    x=datetime.datetime.now()
    return x.strftime("%A.%Y-%m-%d.%H-%M-%S")

def prettyPrint(data):
    print(json.dumps(data, sort_keys=True, indent=4))

def printMenu(title, text, options):
    chooseInput=""
    clearScreen()
    while not chooseInput in options:
        echo("MENU# "+title)
        print()
        print("    ### "+title+" ###")
        print()
        for i in text.split("\n"):
            print("   "+i)
        print()
        for key in options:
            print(key.upper()+" - "+options[key])

        chooseInput=input("==[input]: ").lower()
        clearScreen()
        if not chooseInput in options:
            print("ERROR! unknown option")
    return chooseInput

def clearScreen():
    osName=platform.system()
    if osName=="Windows":
        if mode!="fulldebug":
            os.system("cls")
    elif osName=="Linux":
        if mode!="fulldebug":
            os.system("clear")
    else:
        print("ERROR!!! Not supported os :/ ["+osName+"]")
