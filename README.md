# DAV Scanner - Dockerfile Analysis for Vulnerability Scanner

copyright CNSL, Soongsil University, South Korea

## Installation

### Pre-built binary 

The binary release of **DAV Scanner** supports **Ubuntu 20.04**. For previous Ubuntu version, please update GlibC upto 2.31.

### Build from source

This software is depended on 
* cve-bin-tool::2.0 https://github.com/intel/cve-bin-tool

```python3 setup.py install```

Run ```cve-bin-tool``` first for update the CVE database

* skopeo::1.2.1 https://github.com/containers/skopeo/blob/master/install.md

### Install pre-downloaded CVE database 

```cp *.db ~/.cache/cve-bin-tool/```

### Python 3 and packages:
```
python3 -m pip install colorlog
python3 -m pip install dockerfile-parse
```



## Quick start:

Note: for fully scan the image, something requires root permission:

```$ ./davscanner -i <image name in docker daemon storage> -t <target package name>```

Example:

```$ ./davscanner -i busybox -t nginx```

## Usages

This software may require root permission for scanning fully files in container image.
### Optional arguments:
```
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Original Dockerfile (optional)
  -r, --reverse         Show the reversing result only
  -V, --version         Show version
  -i IMAGE, --image IMAGE
                        Docker image name that wanna scan
  -t TARGET, --target TARGET
                        Target package that want to test on this image
  -o OUTPUT, --output OUTPUT
                        result location
  -L LOG_FILE, --log-file LOG_FILE
                        save log to file
  -d, --debug           print more logs
```

### Reversing Dockerfile from container image

*Note: This function only supports for Docker container image only. Other OCI-based images might be processed. However, the accuracy is not high or program might raise errors.*

```
$ ./davscanner -i busybox -r
*******************DOCKERFILE************************
ADD file:d1deae83af20a79594f83218c2b5bb40c115ee1f9e474377abf84c58f9a7e0e8 in /
CMD ["sh"]
*****************************************************
```

### Scanning image for vulnerable

```
$ sudo ./davscanner -i cve-2018-15473_sshd:latest -t ssh
2021-03-31 13:44:25,660|INFO|Start Scanning phase
2021-03-31 13:44:25,709|INFO|./tmp/skopeo_cve-2018-15473_sshd_latest/blobs/sha256/e33617990d93b2818284c8aae1d7c428d55e80de2ae965d33039b23ef41eab42_tmp/pvf/
2021-03-31 13:44:25,743|INFO|Finish searching PVF for ADD with 964 CVE
2021-03-31 13:44:25,743|INFO|No PVF for CMD
2021-03-31 13:44:25,743|INFO|No PVF for LABEL
2021-03-31 13:44:25,743|INFO|No PVF for MAINTAINER
2021-03-31 13:44:25,747|INFO|./tmp/skopeo_cve-2018-15473_sshd_latest/blobs/sha256/313a52305bee9cc70a82a1b2028b2572a8e7a59984ac1d0b05d8381a6eb36c3e_tmp/pvf/
2021-03-31 13:44:25,752|INFO|Finish searching PVF for ADD with 258 CVE
2021-03-31 13:44:25,752|INFO|No PVF for MAINTAINER
2021-03-31 13:44:25,752|INFO|No PVF for EXPOSE
2021-03-31 13:44:25,752|INFO|No PVF for ENTRYPOINT
2021-03-31 13:44:25,752|INFO|No PVF for CMD
2021-03-31 13:44:25,752|INFO|No PVF for LABEL
2021-03-31 13:44:25,752|INFO|No PVF for MAINTAINER
2021-03-31 13:44:25,752|INFO|Total time: 1.8975915908813477
2021-03-31 13:44:25,753|INFO|Total CVE: 1222
2021-03-31 13:44:25,753|INFO|Total target CVE: 112
2021-03-31 13:44:25,760|INFO|The result is stored at: ./davresult/dav-cve-2018-15473_sshd:latest.json
```

### Result logging

* The analysis result of the image is stored at ```./davresult/``` by default.
* All of the analysis result of **EACH** layer will be stored at ```./log/```
* The image is temporatory stored at ```./tmp/``` during the scanning. Please **DO NOT** delete it. You can debug through analysis by taking a look at this directory.

