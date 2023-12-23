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
# This script identifies module entry point and labels
# efi specific functions, protocols, and guids
# @category UEFISurveyor.headless

from argparse import ArgumentParser
from fnmatch import fnmatch
import json
import os
import sys
from typing import Tuple
from copy import deepcopy


class GFunction:
    def __init__(self, location, name, hash):
        self.hash = hash
        self.location = location
        self.name = name

    def isHash(self, inHash):
        return self.hash == inHash

    def __repr__(self):
        ret = f'Name: {self.name}'
        ret += f', Hash: {self.hash}'
        return ret


class GFunctionContainer:
    def __init__(self, inDict):
        self.matched = []
        self.unmatched = []
        self.parseDict(inDict)

    def parseDict(self, inDict):
        for key in inDict:
            data = GFunction(key, inDict[key][0], inDict[key][1])
            self.addGFunction(data)

    def addGFunction(self, gFunction):
        if gFunction not in self.unmatched and gFunction not in self.matched:
            self.unmatched.append(gFunction)

    def getMatched(self):
        return self.matched

    def getUnMatched(self):
        return self.unmatched

    def hasHash(self, inHash):
        ret = False
        for gFun in self.unmatched:
            if gFun.isHash(inHash):
                self.matched.append(gFun)
                self.unmatched.remove(gFun)
                ret = True
                break
        if not ret:
            for gFun in self.matched:
                if gFun in self.matched:
                    if gFun.isHash(inHash):
                        ret = True
                        break
        return ret


def readFile(filename: str) -> dict:
    with open(filename, 'r') as f:
        contents = f.read()
    return json.loads(contents)


def listDiff(seq1, seq2) -> Tuple[list, list]:
    diff = set(seq1).difference(set(seq2))
    diff2 = set(seq2).difference(set(seq1))
    return (list(diff), list(diff2))


def funcDiff(container1, container2):
    for something in container1.getUnMatched():
        container2.hasHash(something.hash)
    for something in container2.getMatched():
        container1.hasHash(something.hash)


def fileDiff(j1: GFunctionContainer, j2: GFunctionContainer) -> dict:
    res = {}
    funcDiff(j1, j2)
    res['uniqueFunctions1'] = j1.getUnMatched()
    res['uniqueFunctions2'] = j2.getUnMatched()
    return res


def isMismatched(DFDict):
    ret = False
    if DFDict['uniqueFunctions1'] or DFDict['uniqueFunctions2']:
        ret = True
    return ret


def compareDirs(dirpath1, dirpath2):
    res = {}
    json_files = [f.name for f in sorted(os.scandir(dirpath1), key=lambda x: x.name)
                  if fnmatch(f.name, '*json')]
    json_files2 = [f.name for f in sorted(os.scandir(dirpath2), key=lambda x: x.name)
                   if fnmatch(f.name, '*json')]
    diff, diff2 = listDiff(json_files, json_files2)
    res['uniqueFiles1'] = deepcopy(diff)
    res['uniqueFiles2'] = diff2
    res['misMatchedFiles'] = []
    diff += diff2
    for f in json_files:
        if f not in diff:
            j1 = os.path.join(dirpath1, f)
            j2 = os.path.join(dirpath2, f)
            res[f] = compareFiles(j1, j2)
            if isMismatched(res[f]):
                res['misMatchedFiles'].append(f)
    return res


def writeHashFile(results):
    jfile = 'hashlog.json'
    with open(jfile, 'w') as jf:
        jf.write(json.dumps(results, indent=4, default=lambda __o: __o.__dict__))


def compareFiles(filepath1, filepath2):
    jsondata1 = readFile(filepath1)
    file1Container = GFunctionContainer(jsondata1)
    jsondata2 = readFile(filepath2)
    file2Container = GFunctionContainer(jsondata2)
    diff = fileDiff(file1Container, file2Container)
    return diff


if __name__ == '__main__':
    parser = ArgumentParser(prog='comparefile')
    subparsers = parser.add_subparsers()

    # directory command args
    parser_dir = subparsers.add_parser('directory')
    parser_dir.add_argument('arg1', metavar='dir1', type=str, help='filepath of directory')
    parser_dir.add_argument('arg2', metavar='dir2', type=str, help='filepath of directory')
    parser_dir.set_defaults(func=compareDirs)

    # file command args
    parser_file = subparsers.add_parser('file')
    parser_file.add_argument('arg1', metavar='file1', type=str, help='filepath of file')
    parser_file.add_argument('arg2', metavar='file2', type=str, help='filepath of file')
    parser_file.set_defaults(func=compareFiles)

    if len(sys.argv) > 1:
        args = parser.parse_args(sys.argv[1:])
        res = args.func(args.arg1, args.arg2)
        writeHashFile(res)
    else:
        parser.parse_args(['help'])
