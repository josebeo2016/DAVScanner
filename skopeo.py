import os
import utils
import shutil
import logging
import json
import tarfile
logger = logging.getLogger("test")

def oci_splitDigest(str):
    alg = str.split(":")[0]
    digest = str.split(":")[1]
    return alg,digest

class skopeo():
    tmp_dir = "./tmp/"
    def __init__(self,image,containers_storage="docker-daemon",registry="docker.io",format="oci", repo_user=None, repo_pass=None, tls_verify=False):
        if (containers_storage == "docker"):
            self.registry = registry + "/" # Default is docker.io
        else:
            self.registry = ""
        self.format = format # Default manifest-type to use when saving image to directory
        # https://github.com/containers/image/blob/master/docs/containers-transports.5.md#description
        if (containers_storage == "docker"):
            containers_storage = containers_storage + "://"
        else:
            containers_storage = containers_storage + ":"
        self.containers_storage = containers_storage # Default is docker 
        # check tag (optional) [TODO]
        if (":" not in image) and (".tar" not in image):
            # not tag, set default latest
            image = image + ":latest"
        self.image = image
        self.skopeo_path = "skopeo"
        self.repo_user = repo_user
        self.repo_pass = repo_pass
        if (repo_user is not None and repo_pass is not None):
            self.creds = "--src-creds={}:{}".format(self.repo_user, self.repo_pass)
        else:
            self.creds = ""
        
        self.tls_verify = tls_verify

        self.image_storage = ""
        self.commands = []
        self._manifest = None
        self._history = None
        self._layers = []
        self._config = None
        self._dockerfile = None
        # store image to tmp_dir
        # default is: ./tmp/skopeo_image_name_tag/
        self.store_image(os.path.join(self.tmp_dir,"skopeo_{}".format(self.image.replace("/","_").replace(":","_"))))
    
    def store_image(self,dest,is_cache=False):
        if(os.path.isdir(dest)):
            shutil.rmtree(dest,ignore_errors=True)
        logger.debug("Create image dir")
        utils.mkpdirs(dest)

        # check official image from docker hub
        # https://github.com/containers/image/blob/master/docs/containers-transports.5.md#dockerdocker-reference
        image = self.image
        if len(image.split("/")) < 1 and self.registry == "docker.io":
            logger.debug("Official image from docker hub")
            image = "library/{}".format(image)

        if (not is_cache):
            logger.debug("image name: {}".format(image))
            out,err=utils.run_cmd_with_err("{} copy {} {}{}{} oci:{} --src-tls-verify={} --insecure-policy ".format(self.skopeo_path,self.creds,self.containers_storage,self.registry,image,dest,self.tls_verify))
            logger.debug(out)
            logger.debug(err)
        if (not err):
            self.image_storage = dest

    def check_err(self):
        if (self.image_storage == ""):
            logger.error("No image loaded!")
            return -1
    def clean(self):
        shutil.rmtree(os.path.join(self.tmp_dir,"skopeo_{}".format(self.image.replace("/","_").replace(":","_"))))

    def get_manifest(self):
        if (self.image_storage == ""):
            logger.error("No image loaded!")
            return -1
        tmp = utils.read_file(os.path.join(self.image_storage,"index.json"))  
        index_json = ""      
        for line in tmp:
            index_json = index_json + "" + line.strip()
                
        index = json.loads(index_json)
        manifest_file = index["manifests"][0]["digest"]
        manifest_alg,manifest_digest = oci_splitDigest(manifest_file)

        manifest_file = os.path.join(self.image_storage,"blobs",manifest_alg,manifest_digest)

        tmp = utils.read_file(manifest_file)
        manifest_json = ""
        for line in tmp:
            manifest_json = manifest_json + "" + line.strip()
        return json.loads(manifest_json)

    def get_config(self):
        manifest = self.manifest
        config_alg, config_digest = oci_splitDigest(manifest["config"]["digest"])
        config_file = os.path.join(self.image_storage,"blobs",config_alg,config_digest)

        tmp = utils.read_file(config_file)
        config_json = ""
        for line in tmp:
            config_json = config_json + "" + line.strip()

        return json.loads(config_json)
    
    def get_history(self):
        config = self.config
        return config["history"]
    
    def _insert_step(self, step, empty_layer):
        if "#(nop)" in step:
            to_add = step.split("#(nop) ")[1]
        else:
            if (empty_layer==False):
                to_add = ("RUN {}".format(step))
            else:
                to_add = ("MAINTAINER {}".format(step))
        to_add = to_add.replace("&&", "\\\n    &&")
        self.commands.append(to_add.strip(' '))

    def _parse_history(self, rec=False):
        empty_layer = False
        actual_tag = False
        _len = 1
        for i in self.history:

            if("empty_layer" in i):
                empty_layer = True
            self._insert_step(i["created_by"],empty_layer)
        
    def get_layer_dir(self, layer):
        
        manifest = self.manifest
        layers = []
        for i in manifest["layers"]:
            layers.append(i["digest"])
        for i in layers:
            logger.debug(i)
            if (layer in i):
                # logger.debug("im in")
                alg,digest = oci_splitDigest(i)
                return "{}/{}/{}/{}_{}/".format(self.image_storage,"blobs",alg,digest,"tmp"),"{}/{}/{}/{}".format(self.image_storage,"blobs",alg,digest)
        
        return '',''
    def get_file_list(self, layer, isFull=False):
        # print("get_file_list")
        # repo_dir = join(self.tmp_folder, image.repository)
        # blobs_dir = join(repo_dir, 'blobs')
        # self.blobs_dir=blobs_dir
        # image_tar = join(repo_dir, 'image.tar')
        # self.save_image(image, image_tar)
        # with tarfile.open(image_tar) as tar:
        #     tar.extractall(blobs_dir)
        # os.remove(image_tar)
        manifest = self.manifest
        if manifest == -1:
            return []
        layer_tar = ""
        layer_dir = ""
        layer_dir, layer_tar = self.get_layer_dir(layer)
        if (layer_tar == "" or layer_dir == ""):
            return []
        with tarfile.open(layer_tar) as tar:
            utils.mkpdirs(layer_dir)
            tar.extractall(layer_dir)
        if isFull:
            return utils.getListOfFiles(layer_dir,"")
        else:
            return utils.getListOfFiles(layer_dir,layer_dir)

    @property
    def history(self):
        if not self._history:
            self._history = self.get_history()
        return self._history

    @property
    def manifest(self):
        if (self._manifest is None):
            self._manifest = self.get_manifest()
        if (self._manifest == -1):
            return -1
        return self._manifest

    @property
    def config(self):
        if (self._config is None):
            self._config = self.get_config()
        if (self._config == -1):
            return -1
        return self._config

    @property
    def layers(self):
        if not self._layers:
            manifest = self.manifest
            if manifest == -1:
                return []
            for layer in manifest["layers"]:
                # no place for 
                self._layers.append(layer["digest"].split(":")[1])
        return self._layers
    
    @property
    def dockerfile(self):
        if not self._dockerfile:
            self._parse_history()
            # self.commands.reverse()
            self._dockerfile=self.commands
        return self._dockerfile