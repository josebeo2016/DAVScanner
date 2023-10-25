# -*- coding: utf-8 -*-
import logging
import os
from pprint import pformat
from stat import S_ISREG, S_ISDIR
from requests import request
import subprocess

logger = logging.getLogger(__name__)

class File():
    def __init__(self, fullPath, prefix):
        if (len(prefix)>3):  
            self.path = fullPath.replace(prefix,"")
        else:     
            self.path = fullPath
        try:
            self.permission = oct(os.stat(fullPath).st_mode)[-3:]
        except:
            self.permission = '000'

    def __str__(self):
        return "path: {}\t permission: {}".format(self.path,self.permission)

def mkpdirs(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def request_and_check(method, url, **kwargs):
    logger.debug('%s: %s with parameters: %s', method, url, pformat(kwargs))
    resp = request(method, url, **kwargs)
    logger.debug('Response: %s', resp)
    resp.raise_for_status()
    return resp

def getListOfFiles(dirName,prefix):
    # create a list of file and sub directories 
    # names in the given directory 
    try:
        listOfFile = os.listdir(dirName)
    except Exception as e:
        print(e)
        listOfFile = []
    allFiles = list()
    # Iterate over all the entries
    for entry in listOfFile:
        # Create full path
        fullPath = os.path.join(dirName, entry)
        try:
            st = os.lstat(fullPath)
        except EnvironmentError:
            # print ("EnvironmentError")
            continue
        else:
            if S_ISREG(st.st_mode) or S_ISDIR(st.st_mode):
                tmp = File(fullPath,prefix)
                # If entry is a directory then get the list of files in this directory 
                if os.path.isdir(fullPath):
                    allFiles = allFiles + getListOfFiles(fullPath,prefix)
                else:
                    # print("appended")
                    allFiles.append(tmp)    
    return allFiles        


def run_cmd(cmd,timeout=300):
    try:
        process = subprocess.check_output(cmd, shell=True,timeout=timeout)
        # out, error = process.communicate(timeout=200)
        return process.decode('utf-8').strip()
    except Exception as e:
        return "ERROR {}".format(e).strip()

def run_cmd_with_err(cmd,timeout=300):
    process = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    out, error = process.communicate(timeout=timeout)
    return out.decode('utf-8').strip(),error.decode('utf-8').strip()
        
def read_file(file):
    with open(file,"r",encoding="utf-8") as f:
        return f.readlines()