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
from uuid import UUID
import json


def convertGuidStr(name):
    # convert guid from memory
    ret = name[:8]
    ret += name[12:16]
    ret += name[8:12]
    ret += name[22:24]
    ret += name[20:22]
    ret += name[18:20]
    ret += name[16:18]
    ret += name[30:32]
    ret += name[28:30]
    ret += name[26:28]
    ret += name[24:26]
    return ret


def jsonKeystoUUID(inDict):
    outDict = {}
    for key in inDict:
        outDict[UUID(key)] = inDict[key]
    return outDict


class Guids:
    """Class to hold UEFI GUIDs"""
    def __init__(self):
        self.guidDict = {}

    def loadGuidFile(self, filename):
        # load UEFI Guid file
        with open(filename, 'r') as f:
            jsondata = f.read()
        self.guidDict.update(json.loads(jsondata, object_hook=jsonKeystoUUID))

    def getGuidName(self, guid):
        # Return name of GUID
        if guid in self.guidDict.keys():
            return self.guidDict[guid]
        return None

    def logGuids(self):
        # Log Guids extracted from guid file
        logger().log('found the following GUIDS')
        for key in self.guidDict.keys():
            logger.log()('{}, {}'.format(key, self.guidDict[key]))


_guids = Guids()


def guids():
    return _guids
