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

from fnmatch import fnmatch
import json
import os
import sys
from typing import Optional
from uuid import UUID
import yaml


def parseDECfile(filename: str) -> str:
    # Extract the GUID section from a given 'DEC' file
    guid = False
    linein = ""

    with open(filename, 'r') as f:
        for line in f:
            if guid:
                linein += line
            if line.count('[') == 1 and line.count(']') == 1 and (line.find('Guid') > 0 or line.find('Ppis') > 0 or line.find('Protocols') > 0):
                guid = True
            elif line.count('[') == 1 and line.count(']') == 1:
                guid = False
    return linein


def normalizeName(inName: str) -> str:
    # Normalize a GUID name to match what is used within EFISeek
    # Add an _ between names within GUIDS and remove the first letter
    # example gEdkiiDynamicTablesPkgTokenSpaceGuid becomes Edkii_Dynamic_Tables_Pkg_Token_Space_Guid
    outName = inName[0:2]
    for count, letter in enumerate(inName[2:]):
        if letter.isupper() and not inName[count + 1].isupper():
            outName += f"_{letter}"
        else:
            outName += letter
    return outName.upper()


def normalizeGuid(inGuid: str) -> str:
    # Format Guid into a repesentation that can be input to UUID
    alpha = inGuid.lower().replace('{', '').replace(',', ' ').replace('}', '').replace('0x', '').strip()
    outGuid = ''
    i = 0
    for num in alpha.split(' '):
        if len(num) == 0:
            continue
        if i == 0:
            pad = 8
        elif i in [1, 2]:
            pad = 4
        else:
            pad = 2
        outGuid += f'{num.zfill(pad)}'
        i += 1
    return outGuid[:32]


def createDECDict(guid_strings: str, keytype: str = "GUID") -> dict:
    # Guids stored in the following format
    # gEdkiiDynamicTablesPkgTokenSpaceGuid = { 0xab226e66, 0x31d8, 0x4613, { 0x87, 0x9d, 0xd2, 0xfa, 0xb6, 0x10, 0x26, 0x3c } }

    guidDict = {}
    # For each new line get the name and GUID
    for line in guid_strings.split('\n'):
        if len(line) < 20 or line.count('=') == 0:
            continue
        nraw, graw = line.split('=')
        name = normalizeName(nraw.strip()[1:])
        guid = normalizeGuid(graw)
        mguid = f'{UUID(hex=guid)}'
        if keytype.upper() == "NAME":
            key = name
            val = mguid
        else:
            key = mguid
            val = name
        if key in guidDict.keys():
            print(f'Collision found in DEC: {key}, {val}, {guidDict[key]}')
        else:
            guidDict[key] = val
    return guidDict


def parseGUIDFile(filename: str) -> dict:
    # parse a GUID file from either EFISeek or UEFI Surveyor
    # The file will have repeating pattern of [section] followed
    # by entries of name/guid pairs
    linein = ""
    section = {}
    name = ''

    with open(filename, 'r') as f:
        for line in f:
            if line.count('[') == 1 and line.count(']') == 1:
                if name != '':
                    section[name] = linein
                linein = ''
                name = line.strip().replace('[', '').replace(']', '')
            else:
                if line.find('=') > 0:
                    linein += line
        section[name] = linein
    return section


def parseUEFIToolcsv(filename: str) -> dict:
    section = {}
    with open(filename, 'r') as f:
        for line in f:
            if len(line.split(',')) == 2:
                guid, desc = line.split(',')
                # if UUID(guid) in section.keys():
                #     section[UUID(guid)].append(desc)
                # else:
                #     section[UUID(guid)] = [desc]
                section[f'{UUID(guid)}'] = normalizeName(desc.strip())
    return section


def createGUIDDict(guid_strings: str, keytype: str = 'GUID', intype: str = 'GUID') -> dict:
    # Sort via keytype VARIABLE_GUID or NAME
    # VARIABLE_GUID: {72234213-0fd7-48a1-a59f-b41bc107fbcd} = VARIABLE_GUID
    # NAME: VARIABLE_GUID = {72234213-0fd7-48a1-a59f-b41bc107fbcd}
    guidDict = {}
    # For each new line get the name and GUID
    for line in guid_strings.split('\n'):
        if len(line) < 20 or line.count('=') == 0:
            continue
        if intype.upper() == 'NAME':
            name, graw = line.split('=')
        else:
            graw, name = line.split('=')
        tmpguid = graw.lower().replace('{', '').replace('}', '').strip()
        mguid = f'{UUID(tmpguid)}'
        name = name.strip()
        if keytype.upper() == "NAME":
            key = name
            val = mguid
        else:
            key = mguid
            val = name
        if key in guidDict.keys():
            print(f'Collision found in GUID DB: {key}, {val}, {guidDict[key]}')
        else:
            guidDict[key] = val
    return guidDict


def hasKey(dict: dict, key: str) -> Optional[str]:
    # check if a key exists within a dictionary of dictionaries
    for k in dict.keys():
        if key in dict[k].keys():
            return dict[k][key]
    return None


def combineDicts(dict1: dict, dict2: dict, section: str, combine: bool = False) -> None:
    # dict1 is a dictionary of dictionaries sorted by section
    # dict2 is a standard dictionary
    # The function will ensure the section exists then check the
    # dict1 before adding an entry
    if section not in dict1.keys():
        dict1[section] = {}
    for key in dict2.keys():
        isMatch = hasKey(dict1, key)
        print('ismatch', isMatch)
        if combine:
            if isMatch is None:
                dict1[section][key] = [dict2[key]]
            elif dict2[key].strip() not in isMatch:
                isMatch.append(dict2[key].strip())
        else:
            if isMatch is None:
                dict1[section][key] = dict2[key]
            elif isMatch.strip() != dict2[key].strip():
                print(f'Collision found when combining dictionaries: {key}, {isMatch}, {dict2[key]}')


if __name__ == '__main__':
    # open options file and parse
    _file = open('options.yaml')
    data = _file.read()
    _file.close()
    options = yaml.safe_load(data)
    if options['GUIDS']['OUTPUT'] not in ['EFISeek', 'UEFISurveyor']:
        print('Missing output type')
        sys.exit()
    # parse input and combine into output format
    outDict = {}
    if 'COMBINED' in options['GUIDS']:
        combined = options['GUIDS']['COMBINED']
    else:
        combined = False
    print(combined, type(combined))
    for key in options['GUIDS']['INPUT'].keys():
        if options['GUIDS']['INPUT'][key]['TYPE'] == 'DEC':
            if not options['GUIDS']['INPUT'][key]['OPTIONS']:
                for dirpath, dirs, files in os.walk(options['GUIDS']['INPUT'][key]['PATH']):
                    for filename in files:
                        fname = os.path.join(dirpath, filename)
                        if fname.endswith('.dec'):
                            print(f'found file {fname}')
                            tmp = parseDECfile(fname)
                            tmpDB = createDECDict(tmp, 'GUID')
                            combineDicts(outDict, tmpDB, 'EDK', combined)
            else:
                for name in options['GUIDS']['INPUT'][key]['OPTIONS']:
                    filepath = os.path.join(options['GUIDS']['INPUT'][key]['PATH'], name)
                    dec_files = [f.name for f in sorted(os.scandir(filepath), key=lambda x: x.name)
                                 if fnmatch(f.name, '*.dec')]
                    print(f'dec_files {dec_files}')
                    for dec in dec_files:
                        tmp = parseDECfile(os.path.join(filepath, dec))
                        tmpDB = createDECDict(tmp, 'NAME' if options['GUIDS']['OUTPUT'] == 'EFISeek' else 'GUID')
                        combineDicts(outDict, tmpDB, key, combined)
        elif options['GUIDS']['INPUT'][key]['TYPE'] in ['EFISeek', 'UEFISurveyor']:
            sections = parseGUIDFile(options['GUIDS']['INPUT'][key]['PATH'])
            for section in sections.keys():
                tmpDB = createGUIDDict(sections[section], 'NAME' if options['GUIDS']['OUTPUT'] == 'EFISeek' else 'GUID', 'NAME' if options['GUIDS']['INPUT'][key]['TYPE'] == 'EFISeek' else 'GUID')
                combineDicts(outDict, tmpDB, section, combined)
        elif options['GUIDS']['INPUT'][key]['TYPE'] == 'UEFITool':
            sections = parseUEFIToolcsv(options['GUIDS']['INPUT'][key]['PATH'])
            combineDicts(outDict, sections, 'UEFITOOL', combined)

    # write the output into tmp_guid_db file
    with open("tmp_guid_db", 'w') as outfile:
        if options['GUIDS']['OUTPUT'] == 'EFISeek':
            for sect in outDict:
                outfile.writelines(f'[{sect}]\n')
                for key in outDict[sect].keys():
                    outfile.writelines(f'{key} = {{{outDict[sect][key]}}}\n')
        elif options['GUIDS']['OUTPUT'] == 'UEFISurveyor':
            newOut = {}
            for sect in outDict:
                newOut.update(outDict[sect])
            outfile.write(json.dumps(newOut, indent=4))
        elif options['GUIDS']['OUTPUT'] == 'UEFITool':
            for sect in outDict:
                for key in outDict[sect].keys():
                    outfile.writelines(f'{key},{outDict[sect][key]}\n')

    print('\n\nCreated tmp_guid_db')
