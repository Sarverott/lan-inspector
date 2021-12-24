#!/usr/bin/python

# part of Hermes-raports v1.5.0 (file-reader)
# Sett Sarverott
# 2020


#SYSTEM
from system import statisticData as staDa


import gzip
import tarfile
import os
import codecs
import glob

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

def clearDir(dirpath):
    files = glob.glob(dirpath+'/*')
    for f in files:
        os.remove(f)

def safeMkdir(dirpath):
    try:
        os.mkdir(dirpath)
        staDa.echo("dir '"+dirpath+"' created!")
    except FileExistsError:
        staDa.echo("dir '"+dirpath+"' exists!")

def translateGzipFile(infilepath, outfilepath):
    staDa.echo("translation of file '"+infilepath+"', saving as '"+outfilepath+"'...")
    inputFile=gzip.open(infilepath, "r")
    outputFile=open(outfilepath, "w", encoding="utf-8")
    outputFile.write(inputFile.read().decode("utf-8", "slashescape"))
    outputFile.close()
    inputFile.close()

def archiveExtract(archive, path):
    staDa.echo("dearchivization of '"+archive+"' into '"+path+"'...")
    hook=tarfile.open(archive)
    hook.extractall(path)
    hook.close()
