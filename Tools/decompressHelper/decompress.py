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


from collections import namedtuple
from copy import deepcopy
import json
import os
import shutil
import subprocess
from options import loadOptions


decompressProgram = namedtuple("Decompress_Program", ['name', 'type', 'path', 'pythonCommand', 'destination'])


def decompressBinary(options: decompressProgram, binary: str):
    ret = False
    dest = os.path.join(options.destination, f'{options.name}_{os.path.basename(binary)}')
    if options.type == 'UEFIExtract':
        ret = decompressUEFIExtract(options.path, binary)
        if ret:
            ret = parseUEFIExtract(binary, dest)
    elif options.type == 'CHIPSEC':
        ret = decompressCHIPSEC(options.pythonCommand, options.path, binary)
        if ret:
            ret = parseCHIPSEC(binary, dest)
    return ret


def decompressUEFIExtract(exePath, binPath):
    command = [exePath, binPath, 'unpack']
    proc = subprocess.run(command)
    if proc.returncode != 0:
        return False
    return True


# Decompress a binary using UEFIExtract
# Parse the output and copy the efi and te files
# into a folder a separate folder
def parseUEFIExtract(binPath, destName, fileType: str = 'All'):
    reportFile = f'{binPath}.report.txt'
    dump = binPath + '.dump'
    prePE = 'Section_PE32_image_'
    preTE = 'Section_TE_image_'
    post = '_body.bin'
    destPath = destName
    if not os.path.lexists(destPath):
        os.mkdir(destPath)
    if not os.path.isdir(destPath):
        return False
    results = {}
    with open(reportFile, 'r') as report:
        line = report.readline()
        while line:
            msplit = line.replace('  ', '').split('|')
            if msplit[0].strip() == 'File':
                if (fileType == 'All' and msplit[1].strip() not in ['Volume image', 'Pad', 'Freeform', 'Raw']) or (fileType == 'SMM' and msplit[1].strip() == 'SMM module'):
                    if len(msplit) == 7:
                        fname = msplit[5][msplit[5].find(' ', 1):].strip() + '_' + msplit[6].strip().replace(' ', '_')
                    else:
                        fname = msplit[5][msplit[5].find(' ', 1):].strip()
                    if msplit[5][msplit[5].find(' ', 1):].strip() not in results:
                        results[msplit[5][msplit[5].find(' ', 1):].strip()] = {}
                    oldpath = os.path.join(dump, prePE + fname + post)
                    newpath = os.path.join(destPath, fname)
                    if os.path.isfile(newpath):
                        newpath += "_1"
                    if not os.path.isfile(oldpath):
                        oldpath = os.path.join(dump, preTE + fname + post)
                        if not os.path.isfile(oldpath):
                            oldpath = None
                    if oldpath:
                        results[msplit[5][msplit[5].find(' ', 1):].strip()][newpath] = oldpath
                        shutil.copyfile(oldpath, newpath)
            line = report.readline()
    filemapjson = json.dumps(results, indent=2)
    with open(os.path.join(destPath, 'Map.json'), 'w') as f:
        f.write(filemapjson)
    return True


def decompressCHIPSEC(pythonCmd, exePath, binPath):
    command = [pythonCmd, os.path.join(exePath, 'chipsec_util.py'), '-n', '--skip_config', '-nl', 'uefi', 'decode', binPath]
    proc = subprocess.run(command)
    if proc.returncode != 0:
        return False
    return True


def parseCHIPSEC(binPath, destName, fileType: str = 'All'):
    destPath = os.path.join(os.path.dirname(binPath), destName)
    jsonPath = binPath + '.UEFI.json'
    if not os.path.lexists(destPath):
        os.mkdir(destPath)
    if not os.path.isdir(destPath):
        return False
    with open(jsonPath, 'r') as f:
        contents = f.read()
    chipDict = json.loads(contents)
    filemap = recursiveChipsec(chipDict, destPath)
    filemapjson = json.dumps(filemap, indent=2)
    with open(os.path.join(destPath, 'Map.json'), 'w') as f:
        f.write(filemapjson)


def recursiveChipsec(listObj: list, dest: str):
    results = {}
    for module in listObj:
        if 'children' in module:
            res = recursiveChipsec(module['children'], dest)
            for key in res.keys():
                if key not in results.keys():
                    results[key] = res[key]
                elif res[key] == results[key]:
                    continue
                else:
                    for i in res[key].keys():
                        if i not in results[key].keys():
                            results[key][i] = res[key][i]
        if 'class' in module and module['class'] == 'EFI_SECTION':
            if 'Type' in module and module['Type'] in [16, 17, 18, 22]:
                if module['parentGuid'] not in results.keys():
                    results[module['parentGuid']] = {}
                fname = module['parentGuid']
                if module['ui_string']:
                    fname += f'_{module["ui_string"]}'
                elif module['Name']:
                    fname += f'_{module["Name"]}'
                newpath = os.path.join(dest, fname)
                if os.path.isfile(newpath):
                    newpath += "_1"
                results[module['parentGuid']][newpath] = module['file_path']
                shutil.copyfile(module['file_path'], newpath)
    return results


def compareMaps(file1, file2):
    res = {}
    with open(file1, 'r') as f:
        contents = f.read()
    jsondata1 = json.loads(contents)
    with open(file2, 'r') as f:
        contents = f.read()
    jsondata2 = json.loads(contents)
    res['mismatchedFiles'] = []
    diff = list(set(jsondata1.keys()).difference(set(jsondata2.keys())))
    diff2 = list(set(jsondata2.keys()).difference(set(jsondata1.keys())))
    res['uniqueGUIDS1'] = deepcopy(diff)
    res['uniqueGUIDS2'] = diff2
    diff += diff2
    for key in jsondata1.keys():
        if key not in diff:
            if len(jsondata1[key].items()) != len(jsondata2[key].items()):
                res['mismatchedFiles'].append(key)
    return res


if __name__ == '__main__':
    options = loadOptions()
    tools = []
    binaries = []
    for key in options['Decompress']['Program']:
        Type = options['Decompress']['Program'][key].get('Type')
        Path = options['Decompress']['Program'][key].get('Path')
        Destination = options['Decompress']['Destination']
        PythonPath = options['Decompress'].get('Python', None)
        tools.append(decompressProgram(key, Type, Path, PythonPath, Destination))
    for file in options['Decompress']['Binary']['Files']:
        binaries.append(file)
    # add binaries from folders
    for folder in options['Decompress']['Binary']['Folders']:
        for file in os.listdir(folder):
            binaries.append(os.path.join(folder, file))
    # loop through binaries and parse which programs
    for bin in binaries:
        for tool in tools:
            decompressBinary(tool, bin)

    # compare if selected
    if options['Decompress']['Compare']:
        print('Beginning comparison ')
        keys = options['Decompress']['Program'].keys()
        excludelist = []
        if len(keys) > 1:
            for decompress1 in list(keys):
                excludelist.append(decompress1)
                for decompress2 in list(keys)[1:]:
                    if decompress2 in excludelist:
                        continue
                    print(f'Comparing {decompress1} and {decompress2}')
                    for file in binaries:
                        bn = os.path.basename(file)
                        file1 = os.path.join(options['Decompress']['Destination'], f'{decompress1}_{bn}', 'Map.json')
                        file2 = os.path.join(options['Decompress']['Destination'], f'{decompress2}_{bn}', 'Map.json')
                        res = compareMaps(file1, file2)
                        print(f'{decompress1}, {decompress2}, {file}, :')
                        print(res)
