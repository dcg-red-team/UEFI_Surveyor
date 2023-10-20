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


surveyorOptions = namedtuple("surveyorOptions", ['ghidraPath', 'ghidraProject', 'scriptPath', 'guidDBPath', 'gdtPath64', 'gdtPath32', 'projectName', 'efiPath'])


def loadOptions(filename='options.yaml') -> dict:
    try:
        with open(filename, 'r') as f:
            data = f.read()
    except IOError:
        data = ''
    try:
        options = yaml.safe_load(data)
    except yaml.YAMLError:
        options = {}
    return options


def getGhidraOptions(options: dict) -> surveyorOptions:
    ghidrapath = options['Analysis']['Ghidrapath']
    ghidraprojects = options['Analysis']['Projectpath']
    scriptpath = options['Analysis']['Scriptpath']
    guiddbpath = options['Analysis']['GUIDDB']
    gdtpath64 = options['Analysis']['GDT64']
    gdtpath32 = options['Analysis']['GDT32']
    projectname = options['Analysis']['Projectname']
    efipath = options['Analysis']['EFIPath']
    retOptions = surveyorOptions(ghidrapath, ghidraprojects, scriptpath, guiddbpath, gdtpath64, gdtpath32, projectname, efipath)
    return retOptions
