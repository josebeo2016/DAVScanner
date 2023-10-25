# -*- coding: utf-8 -*-
# This source from: https://github.com/joelee2012/claircli/
import logging

from docker.auth import INDEX_NAME, resolve_repository_name
from docker.utils import parse_repository_tag

from docker_registry import DOCKER_HUP_REGISTRY, LocalRegistry, RemoteRegistry

logger = logging.getLogger(__name__)


class Image(object):

    def __init__(self, name, registry=None):
        self.name = name
        self._layers = []
        self._manifest = None
        self._history = None
        self.commands = []
        self._dockerfile = None
        reg, repo, tag = self.parse_id(name)
        self.repository = repo
        self.tag = tag or 'latest'
        if reg == INDEX_NAME:
            reg = DOCKER_HUP_REGISTRY
            self.repository = 'library/{}'.format(repo)
        if isinstance(registry, LocalRegistry):
            self.registry = registry
        else:
            self.registry = RemoteRegistry(reg)



    @classmethod
    def parse_id(cls, name):
        reg_repo, tag = parse_repository_tag(name)
        reg, repo = resolve_repository_name(reg_repo)
        return reg, repo, tag

    def __iter__(self):
        return iter(self.layers)

    def __len__(self):
        return len(self.layers)

    def __str__(self):
        return '<Image: {}>'.format(self.name)

    @property
    def manifest(self):
        if not self._manifest:
            self._manifest = self.registry.get_manifest(self)
        return self._manifest

    @property
    def dockerfile(self):
        if not self._dockerfile:
            self._parse_history()
            self.commands.reverse()
            self._dockerfile=self.commands
        return self._dockerfile
        
    @property
    def history(self):
        if not self._history:
            self._history = self.registry.get_history(self)
        return self._history
 
    @property
    def layers(self):
        if not self._layers:
            manifest = self.manifest
            if isinstance(self.registry, LocalRegistry):
                self._layers = [e.replace('/layer.tar', '')
                                for e in manifest[0]['Layers']]
            elif manifest['schemaVersion'] == 1:
                self._layers = [e['blobSum']
                                for e in manifest['fsLayers']][::-1]
            elif manifest['schemaVersion'] == 2:
                self._layers = [e['digest'] for e in manifest['layers']]
            else:
                raise ValueError(
                    'Wrong schemaVersion [%s]' % manifest['schemaVersion'])
        return self._layers

    def clean(self):
        if isinstance(self.registry, LocalRegistry):
            self.registry.clean_image(self)
    
    def _insert_step(self, step, size):
        if "#(nop)" in step:
            to_add = step.split("#(nop) ")[1]
        else:
            if (size > 0):
                to_add = ("RUN {}".format(step))
            else:
                to_add = ("MAINTAINER {}".format(step))
        to_add = to_add.replace("&&", "\\\n    &&")
        self.commands.append(to_add.strip(' '))

    def _parse_history(self, rec=False):
        first_tag = False
        actual_tag = False
        _len = 1
        for i in self.history:
            if i['Tags']:
                actual_tag = i['Tags'][0]
                if first_tag and not rec:
                    break
                first_tag = True
            else:
                _len = _len + 1
            self._insert_step(i['CreatedBy'],i['Size'])
        if not rec:
            self.commands.append("FROM {}".format(actual_tag))
        
        if len(self.history) == _len:
            self.commands.pop(-1)