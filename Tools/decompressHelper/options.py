# Copyright 2022 Intel Corporation
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
# @category UEFISurveyor.headless

from collections import namedtuple
import yaml


decompressOptions = namedtuple("Decompress_Options", ['binaryPath', 'extractProgram', 'extractPath', 'extractType', 'extractDestination', 'pythonCommand'])


def loadOptions() -> dict:
    try:
        with open('options.yaml', 'r') as f:
            data = f.read()
    except IOError:
        data = ''
    try:
        options = yaml.safe_load(data)
    except yaml.YAMLError:
        options = {}
    return options


def getDecompressOptions(options: dict) -> decompressOptions:
    binaryPath = options['Binary']['Path']
    extractProgram = options['Binary']['Program']
    extractPath = options['Binary']['ProgramPath']
    extractType = options['Binary']['FileType']
    extractDest = options['Binary']['Destination']
    extractPython = options['Binary'].get('Python', None)
    decOptions = decompressOptions(binaryPath, extractProgram, extractPath, extractType, extractDest, extractPython)
    return decOptions
