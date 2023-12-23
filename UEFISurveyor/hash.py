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

import json


class HashStore:
    """Class to hold UEFI Function Hashes"""
    def __init__(self):
        self.inHashDict = {}
        self.outHashDict = {}

    def loadHashFile(self, filename):
        # load UEFI Function Hashes file
        with open(filename, 'r') as f:
            jsondata = f.read()
        self.inHashDict.update(json.loads(jsondata))

    def getFuncName(self, hashStr):
        # Return name of GUID
        if hashStr is not None:
            if hashStr.toString() in self.inHashDict.keys():
                print('found', self.inHashDict[hashStr.toString()])
                return self.inHashDict[hashStr.toString()]
        return None

    def addHash(self, hashStr, func):
        self.outHashDict[func.getEntryPoint().toString()] = (func.toString(), hashStr)

    def logHashes(self, programFile):
        funcsJson = json.dumps(self.outHashDict, indent=4)
        outfile = '{}.json'.format(programFile)
        with open(outfile, 'w') as jsonout:
            jsonout.write(funcsJson)


_hashes = HashStore()


def fnHashes():
    return _hashes
