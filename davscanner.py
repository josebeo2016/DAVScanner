from argparse import ArgumentParser
import logging
import sys
import argparse
import json
import colorlog
from dockerfile_parse import DockerfileParser
import re
import subprocess
import os
import shutil
import utils
import yaml

from skopeo import skopeo
#from docker_registry import LocalRegistry
#from docker_image import Image
logger = logging.getLogger("test")
import time
_WORKDIR = ""
_ENV = {}
_BLOBS_DIR = ""
VERSION = "2.1"
def pvf_condition(f):
    if f.permission.find("1")!=-1 or f.permission.find("3")!=-1 or f.permission.find("5")!=-1 or f.permission.find("7")!=-1:
        return True
    return False

class Result():
    package = ""
    version = ""
    cve = ""
    severity = ""
    def __init__(self,package,version,cve_number,severity):
        self.package = package
        self.version = version
        self.cve = cve_number
        self.severity = severity
    


class Instruction():
    
    _instruction = ""
    _args=""
    _isLayer = False
    _layer = ""
    _fileList = []
    _PVF = []
    _layer_dir = ""
    _result = []
    def __init__(self,line):
        self._instruction = line['instruction']
        self._args = line['value']
        self.setup()
    def setup(self):
        logger.debug(self._instruction)
        logger.debug(self._args)
    
    def setFileList(self,fileList):
        if self._isLayer:
            self._fileList = fileList
    
    def getPVF(self):
        # DO NOTHING
        logger.debug("Start searching for PVF in {}".format(self._instruction))
    # def getExecList(self):
    def copyPVF(self):
        PVF_dir = os.path.join(self._layer_dir,"pvf/")
        for f in self._PVF:
            shutil.copyfile(f.path,PVF_dir)
        
        
        
class WORKDIR(Instruction):
    def setup(self):
        global _WORKDIR
        self._PVF=[]
        self._result = []
        _WORKDIR = self._args

class ENV(Instruction):
    def setup(self):
        global _ENV
        self._PVF=[]
        self._result = []
        key = self._args.split("=")[0]
        value = self._args.split("=")[1]
        logger.debug("key:{}".format(key))
        logger.debug("value:{}".format(value))
        _ENV[key]=value

class CMD(Instruction):
    def setup(self):
        self._PVF=[]
        self._result = []
        # self._instruction = "CMD"
        cmd = self._args
        cmd = cmd.replace("[","").replace("\\\\","\\").replace("\\\"","\"").replace("]","")
        if ('/bin/sh" "-c" "' in cmd):
            _args = cmd.replace('/bin/sh" "-c" "',"")[1:-1].split(" ")
        else:
            _args = cmd.replace("\"","").split(" ")
        self._args = _args
        logger.debug(self._instruction)
        logger.debug(self._args)
        # self.bin=_args[0]
        # self._args=_args[1:]
    # def getPVF(self):
    #     logger.debug("Start searching for PVF in {}".format(self._instruction))
    #     self._PVF.append(_WORKDIR+"/"+self._args[0].replace("./",""))
    #     return len(self._PVF)

class ENTRYPOINT(Instruction):
    def setup(self):
        self._PVF=[]
        self._result = []
        # self._instruction = "ENTRYPOINT"
        cmd = self._args
        cmd = cmd.replace("[","").replace("\\\\","\\").replace("\\\"","\"").replace("]","")
        if ('/bin/sh" "-c" "' in cmd):
            _args = cmd.replace('/bin/sh" "-c" "',"")[1:-1].split(" ")
        else:
            _args = cmd.replace("\"","").split(" ")
        self.bin=_args[0]
        self._args=_args[1:]
        logger.debug(self._instruction)
        logger.debug(self.bin)
        logger.debug(self._args)
    
    # def getPVF(self):
    #     logger.debug("Start searching for PVF in {}".format(self._instruction))
    #     self._PVF.append(_WORKDIR+"/"+self.bin)
    #     return len(self._PVF)

class RUN(Instruction):
    download_re="(wget|curl).*(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?"
    def setup(self):
        self._PVF=[]
        self._result = []
        self._isLayer = True
        # self._instruction = "RUN"
        # Replace environment value in RUN command:
        for key,value in _ENV.items():
            self._args=self._args.replace("${}".format(key),value)
            # logger.debug(key)

        self.cmds=self._args.replace("|","&&").replace(";","&&").split("&&")
        self.urls=re.findall(self.download_re,"\n".join(self.cmds))
        logger.debug(self._instruction)
        logger.debug(self.urls)
    
    def getPVF(self):
        logger.debug("Start searching for PVF in {}".format(self._instruction))
        PVF_dir = os.path.join(self._layer_dir,"pvf/")
        utils.mkpdirs(PVF_dir)
        if len(self.urls)==0:
            self._PVF = []
            return 0           
        for f in self._fileList:
            if pvf_condition(f):
                self._PVF.append(f.path)
                try:
                    shutil.copy(f.path,PVF_dir)
                except Exception as e:
                    logger.warning("getPVF(): {}".format(e))
                    pass
            else:
                continue
        
        return len(self._PVF)

class COPY(Instruction):
    def setup(self):
        self._PVF=[]
        self._result = []
        self._isLayer = True
        # self._instruction = "ADD"
        _file = self._args.split(" ")[-1]
        self._dst = self._args.split(" ")[-1]
        head, tail = os.path.split(_file)
        if tail:
            self._type="file"
        else:
            self._type="dir"
        logger.debug(self._instruction)
        logger.debug(self._dst)
        logger.debug(self._type)

class ADD(Instruction):
    def setup(self):
        self._PVF=[]
        self._result = []
        self._isLayer = True
        # self._instruction = "ADD"
        _file = self._args.split(" ")[-1]
        self._dst = self._args.split(" ")[-1]
        head, tail = os.path.split(_file)
        if tail:
            self._type="file"
        else:
            self._type="dir"
        logger.debug(self._instruction)
        logger.debug(self._dst)
        logger.debug(self._type)
    
    def setFileList(self,fileList):
        # if self._type == "file":
        #     self._fileList = [utils.File(self._dst,"")]
        # else:
        super().setFileList(fileList)

    def getPVF(self):
        logger.debug("Start searching for PVF in {}".format(self._instruction))
        PVF_dir = os.path.join(self._layer_dir,"pvf/")
        utils.mkpdirs(PVF_dir)
        for f in self._fileList:
            if pvf_condition(f):
                self._PVF.append(f.path)
                try:
                    shutil.copy(f.path,PVF_dir)
                except Exception as e:
                    logger.warning("getPVF(): {}".format(e))
                    pass
            else:
                continue
        return len(self._PVF)

class FROM(Instruction):
    def setup(self):
        self._PVF=[]
        self._result = []
        self._isLayer = True
        self.baseOS = self._args
        logger.debug(self._instruction)
        logger.debug(self.baseOS)
    
    def setFileList(self,fileList):
        # DO NOT NEED to set file list for FROM Instruction
        self._fileList = []
    
    def getPVF(self):
        logger.debug("Start searching for PVF in {}".format(self._instruction))
        return 0

class Parser():
    description = """
    Dockerfile Analysis for Vulnerability Scanner
    Copyright CNSL, Soongsil University
    """
    def __init__(self):
        # common options
        opt = ArgumentParser(
            description=self.description,
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        opt.add_argument(
            "-f","--file",
            help="Original Dockerfile (optional)"
        )
        opt.add_argument(
            "-r", "--reverse", action="store_true",
            help="Show the reversing result only"
        )
        opt.add_argument(
            "-V", "--version", action="store_true",
            help="Show version"
        )
        opt.add_argument("-i","--image",
            help="Docker image name that wanna scan")
        opt.add_argument("-t","--target", default="",
            help="Target package that want to test on this image")
        opt.add_argument('-o', '--output', help='result location')
        opt.add_argument('-L', '--log-file', help='save log to file')
        opt.add_argument(
            '-d', '--debug', action='store_true', help='print more logs')
        
        opt.add_argument(
            "-S", "--container_storage", 
            help="""Based on types that are supported by skopeo, the container storage could be:
                (*) docker-daemon (default)
                () oci
                () oci-archive
                () docker-archive
                () docker
                () dir
                
                The image name (or FULL file/dir path) can be put into the scanner by using option [-i]
                ref:https://github.com/containers/image/blob/master/docs/containers-transports.5.md
            """
        )
        opt.add_argument(
            "-R", "--registry",
            help="Container registry. Example: docker.io, quay.io. Note: authentication to registry is not supported yet!"
        )

        opt.set_defaults(func=self.parse_file)
        self.args = opt.parse_args()
        with open("config.yaml", "r") as stream:
            try:
                self.conf = yaml.safe_load(stream)
                self.args 
            except yaml.YAMLError as exc:
                print(exc)

        if (len(sys.argv)==1):
            opt.print_help()
            sys.exit(1)
        self.setup_logging()
    
    def setup_logging(self):
        # Setup environment:
        utils.mkpdirs("./davresult/")
        utils.mkpdirs("./log/")
        utils.mkpdirs("./tmp/")
        # logger = logging.getLogger('parser')
        console_formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s|%(levelname)s|%(message)s')
        file_formatter = logging.Formatter(
            '%(asctime)s|%(levelname)s| %(message)s')
        stdout = colorlog.StreamHandler(sys.stdout)
        stdout.setFormatter(console_formatter)
        logger.addHandler(stdout)
        logger.setLevel(logging.INFO)
        if self.args.debug:
            logger.setLevel(logging.DEBUG)
        if self.args.log_file:
            handler = logging.FileHandler(self.args.log_file, 'w', delay=True)
            handler.setFormatter(file_formatter)
            logger.addHandler(handler)

    def parse_file(self):
        # registry = LocalRegistry("127.0.0.1")
        # image = Image(self.args.image,registry) # old image lib
        # OCI image using skopeo
        
        if (self.args.version):
            print("DAV Sacnner {} - Developed by Phucdt - CNSL, Soongsil University".format(VERSION))
            return
        repo_storage = self.conf["repo_storage"]
        repo_regis = self.conf["repo_regis"]
        repo_user = self.conf["repo_user"]
        repo_pass = self.conf["repo_pass"]
        registry_tls_verify = self.conf["registry_tls_verify"]

        if (self.args.container_storage):
            repo_storage = self.args.container_storage 
        if (self.args.registry):
            repo_regis = self.args.registry
            
        image = skopeo(self.args.image,containers_storage=repo_storage,registry=repo_regis,repo_user=repo_user, repo_pass=repo_pass, tls_verify=registry_tls_verify)
        # check image error:
        if (image.check_err()==-1):
            return
        layers = image.layers
        start_time = time.time()
        # dfp = DockerfileParser(path="./tmp/Dockerfile")
        dfp = DockerfileParser()
        if (self.args.reverse):
            print("*******************DOCKERFILE************************")
            for i in image.dockerfile:
                print(""+i)
            print("*****************************************************")
            image.clean()
            return
        if (not self.args.file):
            dfp.content = "\n".join(image.dockerfile)
        else:
            with open(self.args.file,'r',encoding='utf-8') as f:
                dfp.content = f.read()
        
        # clean Dockerfile
        _ = subprocess.check_output("rm -rf ./tmp/Dockerfile",shell=True)

        Instructions = []
        for line in dfp.structure:
            if (line['instruction']=="ADD" or line['instruction']=="COPY"):
                Instructions.append(ADD(line))
            elif (line['instruction']=="RUN"):
                Instructions.append(RUN(line))
            elif (line['instruction']=="CMD"):
                Instructions.append(CMD(line))
            elif (line['instruction']=="ENTRYPOINT"):
                Instructions.append(ENTRYPOINT(line))
            elif (line['instruction']=="FROM"):
                Instructions.append(FROM(line))
            elif (line['instruction']=="ENV"):
                Instructions.append(ENV(line))
            else:
                Instructions.append(Instruction(line))
    
        logger.debug("++++++++++++++++++++Manifest++++++++++++++++++++++++")
        logger.debug(image.manifest)
        # TODO
        i = 0
        for intr in Instructions:
            if (intr._isLayer):
                result = os.path.join("./log/","{}_result.json".format(intr._layer))
                if (os.path.isfile(result)):
                    logger.info("This layer is already scanned! {}".format(intr._layer))
                    continue
                logger.debug("Instruction {} mapping ...".format(intr._instruction))
                try:
                    intr._layer = layers[i]
                except Exception as e:
                    logger.error(layers[-1])
                    intr._layer = layers[-1]
                # intr.setFileList(registry.get_file_list(image,intr._layer,isFull=True))
                intr.setFileList(image.get_file_list(intr._layer,isFull=True))
                layer_dir, layer_tar = image.get_layer_dir(intr._layer)
                intr._layer_dir = layer_dir
                i=i+1
        # only set blobs_dit after get_file_list()
        global _BLOBS_DIR
        # _BLOBS_DIR = registry.blobs_dir
        # _BLOBS_DIR = "{}/"

        # debug
        for intr in Instructions:
            logger.debug("Intrucion: {} map with Layer: {}".format(intr._instruction,intr._layer))
            if (len(intr._fileList)>0):
                logger.debug("File[0]: {} {}".format(intr._fileList[0].path,intr._fileList[0].permission))
        
        # Test phase
        logger.info("Start Scanning phase")
        # List all potentially vulnerable files will be done on init
        CVE_count = 0
        target_list = []
        for intr in Instructions:
            if (intr.getPVF()):
                # Call CVE-Bin-Scan
                # PVF_dir = os.path.join(_BLOBS_DIR,intr._layer,"pvf/")
                layer_dir, layer_tar = image.get_layer_dir(intr._layer)
                PVF_dir = os.path.join(layer_dir,"pvf/")
                logger.debug("PVF DIR: "+PVF_dir)
                result = os.path.join("./log/","{}_result.json".format(intr._layer))
                if (os.path.isfile(result) is not True):
                    try:
                        out=subprocess.check_output("cve-bin-tool -u never --nvd-api-key {} {} -f json -o {} -x".format(self.conf["nvd_api_key"],PVF_dir,result),shell=True)
                        # logger.info(out)
                    except Exception as e:
                        logger.error(e)
                logger.info(PVF_dir)

                # result = os.path.join(PVF_dir,"result.json")
                if os.path.isfile(result):
                    with open(result) as json_file:
                        data = json.load(json_file)
                        CVE_count = CVE_count + len(data)
                        # parse data
                        for p in data:
                            # logger.debug("{}".format(json.dumps(p,indent=4)))
                            intr._result.append({"package":p["product"],"version":p['version'],"cve":p['cve_number'],"severity":p['severity']})
                logger.debug("{}".format(intr._result))
                for p in intr._result:
                    if self.args.target in p["package"]:
                        target_list.append(p)
                logger.info("Finish searching PVF for {} with {} CVE".format(intr._instruction,len(intr._result)))
                logger.debug("PVF len: "+str(len(intr._PVF))) 
            else:
                logger.info("No PVF for {}".format(intr._instruction))
        


        logger.info("Total time: {}".format(time.time()-start_time))
        logger.info("Total CVE: {}".format(CVE_count))
        # Target CVE
        # Debug
        logger.info("Total target CVE: {}".format(len(target_list)))
        for a in target_list:
            logger.debug(a["cve"])
            logger.debug(a["package"])
        
        # Write result to file
        all_cve=[]
        for intr in Instructions:
            all_cve=all_cve+intr._result
        if (self.args.output):
            result_json = self.args.output
        else:
            result_json = "./davresult/dav-{}.json".format(self.args.image.replace("/","_"))
        with open(result_json,"w") as outfile:
            json.dump(all_cve,outfile,indent=4)
        logger.info("The result is stored at: {}".format(result_json))
        # print(image.manifest)
        # print(registry.get_file_list(image,layers[2],isFull=True))
        image.clean()


    def run(self):
        return self.args.func()

class LoopParser():
    description = """
    Dockerfile Parser for a list of image
    """
    def __init__(self,image,target,containers_storage="docker-daemon",registry="docker.io"):
        # common options

        self.image = image
        self.target = target
        self.debug = None
        self.log_file = "dac.log"
        self.file=None
        self.registry = registry
        self.containers_storage = containers_storage
        self.setup_logging()
    
    def setup_logging(self):
        # logger = logging.getLogger('parser')
        console_formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s|%(levelname)s|%(message)s')
        file_formatter = logging.Formatter(
            '%(asctime)s|%(levelname)s| %(message)s')
        stdout = colorlog.StreamHandler(sys.stdout)
        stdout.setFormatter(console_formatter)
        logger.addHandler(stdout)
        logger.setLevel(logging.INFO)
        if self.debug:
            logger.setLevel(logging.DEBUG)
        if self.log_file:
            handler = logging.FileHandler(self.log_file, 'w', delay=True)
            handler.setFormatter(file_formatter)
            logger.addHandler(handler)

    def parse_file(self):
        # registry = self.registry
        # image = Image(self.args.image,registry) # old image lib
        # OCI image using skopeo
        image = skopeo(self.image,containers_storage=self.containers_storage)
        layers = image.layers
        start_time = time.time()
        dfp = DockerfileParser()
        if (not self.file):
            dfp.content = "\n".join(image.dockerfile)
        else:
            with open(self.file,'r',encoding='utf-8') as f:
                dfp.content = f.read()
        Instructions = []
        for line in dfp.structure:
            if (line['instruction']=="ADD" or line['instruction']=="COPY"):
                Instructions.append(ADD(line))
            elif (line['instruction']=="RUN"):
                Instructions.append(RUN(line))
            elif (line['instruction']=="CMD"):
                Instructions.append(CMD(line))
            elif (line['instruction']=="ENTRYPOINT"):
                Instructions.append(ENTRYPOINT(line))
            elif (line['instruction']=="FROM"):
                Instructions.append(FROM(line))
            elif (line['instruction']=="ENV"):
                Instructions.append(ENV(line))
            else:
                Instructions.append(Instruction(line))
    
        logger.debug("++++++++++++++++++++Manifest++++++++++++++++++++++++")
        logger.debug(image.manifest)
        # TODO
        i = 0
        for intr in Instructions:
            if (intr._isLayer):
                result = os.path.join("./log/","{}_result.json".format(intr._layer))
                if (os.path.isfile(result)):
                    logger.info("This layer is already scanned! {}".format(intr._layer))
                    continue
                logger.debug("Instruction {} mapping ...".format(intr._instruction))
                try:
                    intr._layer = layers[i]
                except Exception as e:
                    logger.error(layers[-1])
                    intr._layer = layers[-1]
                # intr.setFileList(registry.get_file_list(image,intr._layer,isFull=True))
                intr.setFileList(image.get_file_list(intr._layer,isFull=True))
                layer_dir, layer_tar = image.get_layer_dir(intr._layer)
                intr._layer_dir = layer_dir
                i=i+1
        # only set blobs_dit after get_file_list()
        global _BLOBS_DIR
        # _BLOBS_DIR = registry.blobs_dir
        # _BLOBS_DIR = "{}/"

        # debug
        for intr in Instructions:
            logger.debug("Intrucion: {} map with Layer: {}".format(intr._instruction,intr._layer))
            if (len(intr._fileList)>0):
                logger.debug("File[0]: {} {}".format(intr._fileList[0].path,intr._fileList[0].permission))
        
        # Test phase
        logger.info("Start Scanning phase")
        # List all potentially vulnerable files will be done on init
        CVE_count = 0
        target_list = []
        for intr in Instructions:
            if (intr.getPVF()):
                # Call CVE-Bin-Scan
                # PVF_dir = os.path.join(_BLOBS_DIR,intr._layer,"pvf/")
                layer_dir, layer_tar = image.get_layer_dir(intr._layer)
                PVF_dir = os.path.join(layer_dir,"pvf/")
                logger.debug("PVF DIR: "+PVF_dir)
                result = os.path.join("./log/","{}_result.json".format(intr._layer))
                if (os.path.isfile(result) is not True):
                    try:
                        out=subprocess.check_output("cve-bin-tool {} -f json -o {} -x".format(PVF_dir,result),shell=True)
                        # logger.info(out)
                    except Exception as e:
                        logger.error(e)
                logger.info(PVF_dir)

                # result = os.path.join(PVF_dir,"result.json")
                if os.path.isfile(result):
                    with open(result) as json_file:
                        data = json.load(json_file)
                        CVE_count = CVE_count + len(data)
                        # parse data
                        for p in data:
                            logger.debug("{}".format(json.dumps(p,indent=4)))
                            intr._result.append({"package":p["product"],"version":p['version'],"cve":p['cve_number'],"severity":p['severity']})

                for p in intr._result:
                    if self.target in p["package"]:
                        target_list.append(p)
                logger.info("Finish searching PVF for {} with {} CVE".format(intr._instruction,len(intr._result)))
                logger.debug("PVF len: "+str(len(intr._PVF))) 
            else:
                logger.info("No PVF for {}".format(intr._instruction))
        


        logger.info("Total time: {}".format(time.time()-start_time))
        logger.info("Total CVE: {}".format(CVE_count))
        # Target CVE
        # Debug
        logger.info("Total target CVE: {}".format(len(target_list)))
        for a in target_list:
            logger.debug(a["cve"])
            logger.debug(a["package"])
        
        # Write result to file
        all_cve=[]
        for intr in Instructions:
            all_cve=all_cve+intr._result
        result_json = "./davresult/dav-{}.json".format(self.image.replace("/","_"))
        with open(result_json,"w") as outfile:
            json.dump(all_cve,outfile,indent=4)
        # print(image.manifest)
        # print(registry.get_file_list(image,layers[2],isFull=True))
        image.clean()
        return all_cve



def main():
    # start_time = time.time()
    cli = Parser()
    sys.exit(cli.run())
    # logger.info("Total time: {}".format(time.time()-start_time))


if __name__ == "__main__":
    # start_time = time.time()
    main()
    # logger.info("Total time: {}".format(time.time()-start_time))

