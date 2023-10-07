# Copyright 2023 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# @category UEFISurveyor.internal

from logger import logger


class Artifacts:
    # Class that keeps track of changes made to EFI file
    # Includes guids, protocols, labels, and functions
    def __init__(self):
        self.guids = {}
        self.protocols = {}
        self.localProtocols = {}
        self.labels = {}
        self.functions = {}
        self.notify = {}

    def add_guid(self, address, name, bytes):
        if address in self.guids.keys():
            logger().log("Guid already defined at address {} - {}".format(address, self.guids[address]))
        self.guids[address] = (name, bytes)

    def get_guid(self, address):
        ret = (None, None)
        if address in self.guids.keys():
            ret = self.guids[address]
        return ret

    def add_protocol_global(self, address, name, datatype, origin):
        if address in self.protocols.keys():
            logger().log("protocol already defined for address {} - {}".format(address, self.protocols[address]))
        self.protocols[address] = (name, datatype, origin)

    def has_protocol_global(self, address):
        if address in self.protocols.keys():
            return True
        return False

    def add_protocol_local(self, function, location, name, datatype):
        if name in self.localProtocols.keys():
            logger().log("duplicate key found adding local protocol")
        self.localProtocols[name] = (function, location, datatype)

    def add_label(self, address, name, datatype):
        if address in self.labels.keys():
            logger().log("duplicate key found adding label")
        self.labels[address] = (name, datatype)

    def has_label(self, address):
        if address in self.labels.keys():
            return True
        else:
            return False

    def add_function(self, address, name):
        if address in self.functions:
            logger().log('Renaming funciton at {}'.format(address))
        self.functions[address] = name

    def add_notify(self, name, event):
        self.notify[name] = event

    def logArtifacts(self):
        logger().log('')
        logger().log('Identified the following Guids')
        for key in self.guids.keys():
            logger().log("{} - {}".format(self.guids[key][0], key))
        logger().log('')
        logger().log('Identified the following protocols')
        for key in self.protocols.keys():
            logger().log("{} - {}".format(key, self.protocols[key]))
        logger().log('')
        for key in self.localProtocols.keys():
            logger().log("{} - {}".format(key, self.localProtocols[key]))
        logger().log('')
        logger().log('Applied the following labels:')
        for key in self.labels.keys():
            logger().log("{} - {}".format(key, self.labels[key]))
        logger().log('')
        logger().log('Identified the following functions:')
        for key in self.functions.keys():
            logger().log("{} - {}".format(key, self.functions[key]))
        logger().log('')
        logger().log('Notify Handlers registered events:')
        for key in self.notify.keys():
            logger().log('{} - {}'.format(key, self.notify[key]))
        logger().log('')


_Artifacts = Artifacts()


def artifacts():
    return _Artifacts
