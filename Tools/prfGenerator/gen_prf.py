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

import os
import sys
from typing import Union
import yaml


def getRequired(lpath: str, entry: Union[dict, list, str]) -> list:
    rl = []
    if isinstance(entry, dict):
        for key in entry.keys():
            rl += getRequired(os.path.join(lpath, key), entry[key])
    if isinstance(entry, list):
        for key in entry:
            rl += getRequired(lpath, key)
    if isinstance(entry, str):
        rl.append(os.path.join(lpath, entry))
    return rl


def genHeaders(pkg_list: list, localpath: str, nodirs: list) -> str:
    ret = ''
    for pkg in pkg_list:
        for root, dirs, files in os.walk(os.path.join(localpath, pkg, "Include")):
            for file in files:
                if file.endswith('.h') and not any(root.endswith(i) for i in nodirs):
                    ret += "{}\n".format(os.path.join(root, file))
    return ret


def genIncludes(pkg_list: list, localpath: str) -> str:
    ret = ''
    for pkg in pkg_list:
        ret += '{}\n'.format(os.path.join(localpath, pkg, "Include"))
    return ret


if __name__ == '__main__':
    ARCHS = ["X64", "Arm", "Ebc", "Ia32", "RiscV", "RiscV64", "AArch64"]
    # read in options.yaml
    _file = open('options.yaml')
    data = _file.read()
    options = yaml.safe_load(data)
    # ensure ARCH is within know architectures
    if 'ARCH' not in options or options['ARCH'] not in ARCHS:
        print(f"Missing valid architecture please provide one from the list {' '.join(i for i in ARCHS)}")
        sys.exit()
    # list of directories not to include
    nodirs = [i for i in ARCHS if i != options['ARCH']]
    # set name of outfile
    filename = 'uefi_{}.prf'.format(options['ARCH']).lower()
    # check to ensure configuration contains proper information
    if 'HEADERS' not in options or 'EDK2' not in options['HEADERS']:
        print('Missing EDK2')
        sys.exit()
    if 'PKGS' not in options['HEADERS']['EDK2']:
        print('Missing PKGS')
        sys.exit()
    # create prf file
    with open(filename, 'w') as outfile:
        for req in getRequired(options['HEADERS']['EDK2']['PATH'], options['REQUIRED']):
            outfile.writelines(f'{req}\n')
        for mname in options['HEADERS'].keys():
            outfile.writelines(genHeaders(options['HEADERS'][mname]['PKGS'], options['HEADERS'][mname]['PATH'], nodirs))
        outfile.writelines('\n\n')
        outfile.writelines('{}\n'.format(os.path.join(options['HEADERS']['EDK2']['PATH'], "MdePkg", "Include", options['ARCH'])))
        outfile.writelines('{}\n'.format(os.path.join(options['HEADERS']['EDK2']['PATH'], "MdePkg", "Include", "Library")))
        for mname in options['HEADERS'].keys():
            outfile.writelines(genIncludes(options['HEADERS'][mname]['PKGS'], options['HEADERS'][mname]['PATH']))
    print(f'Successfully generated {filename}')
