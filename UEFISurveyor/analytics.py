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
from ghidra.app.decompiler.component import DecompilerUtils
from EFI_functs import EFIUtils
from logger import logger
from artifacts import artifacts
from ghidra.feature.fid.service import FidService


class CallOuts:
    def __init__(self, name, func_list):
        self.name = name
        self.funcs = func_list
        self.callouts = []

    def get_funcs(self):
        return self.funcs

    def add_callout(self, func, handler, path):
        self.callouts.append((func, handler, path))

    def log_results(self):
        if not self.callouts:
            logger().log("Did not find any callouts in from {}".format(self.name))
            logger().log('')
        else:
            for (func, handler, path) in self.callouts:
                logger().log("Potential Callout:")
                logger().log('{} has callpath {} to {} with {}'.format(handler, path, func, self.name))


class EFIAnalytics(EFIUtils):

    def __init__(self, currentProgram):
        super(EFIAnalytics, self).__init__(currentProgram)

    def identifyCallouts(self):
        logger().log('Searching for potential callouts')
        # Gather the functions that contain gBS and gRS
        refs = []
        gbsrefs = self.getSymbolRefs("gBS")
        refs.append(CallOuts('gBS', self.getUniqueFuncts(gbsrefs)))

        grsrefs = self.getSymbolRefs("gRS")
        refs.append(CallOuts('gRS', self.getUniqueFuncts(grsrefs)))

        # Gather any artifacts that came from gRT or gBS
        for key in artifacts().protocols.keys():
            name, _, origin = artifacts().protocols[key]
            if origin == 'gBS' and name not in ['gBS', 'gRS']:
                globalrefs = self.getSymbolRefs(name, True)
                refs.append(CallOuts(name, self.getUniqueFuncts(globalrefs)))

        # Enumerate the SMIHandlers
        # search for a callpath that goes to a function with the handler
        funcMan = self.currentProgram.getFunctionManager()
        for func in [func for func in funcMan.getFunctions(True) if func.getName().find("Handler") >= 0]:
            for ref in refs:
                for gfunc in ref.get_funcs():
                    emptylist = []
                    fnPath = self.isFunctionPath(func, [gfunc], emptylist)
                    if fnPath:
                        ref.add_callout(gfunc, func, fnPath)
        for ref in refs:
            ref.log_results()
        logger().log('')

    # Crude check Within handler functions check whether commbuffer is dereferenced multiple times
    # The theory is that the data should be copied and worked on by a local buffer if there are multiple
    # times that it is dereferenced that may indicsate that a potential TOCTOU window
    # @TODO add savestate registers
    def identifyTOCTOU(self):
        funcMan = self.currentProgram.getFunctionManager()
        for func in [func for func in funcMan.getFunctions(True) if func.getName().find("swSmiHandler") >= 0]:
            hf = self.get_high_function(func)
            lsm = hf.getLocalSymbolMap()
            symbols = lsm.getSymbols()

            for symbol in symbols:
                if symbol.getName() != "CommBuffer":
                    continue
                hv = symbol.getHighVariable()
                varnode = hv.getRepresentative()
                fswo = DecompilerUtils.getForwardSliceToPCodeOps(varnode)
                count = 0
                for f in fswo:
                    if "LOAD" in str(f):
                        count += 1
                logger().log("{} CommBuffer is dereferenced {} times".format(func, count))

    # Find the uses of GetVariable and SetVariable within a function
    def identifyVariableUses(self):
        logger().log('Searching for (G/S)ET_VARIABLE:')
        funcMan = self.currentProgram.getFunctionManager()
        found = False
        for func in funcMan.getFunctions(True):
            results = self.functionVariableUse(func)
            if results:
                found = True
                logger().log('{}:'.format(func))
                for key in results.keys():
                    logger().log("  {}:".format(key))
                    for element in results[key]:
                        logger().log('    {}'.format(element))
        if not found:
            logger().log('Did not find any instances of (G/S)ET_VARIABLE')
        logger().log('')

    def getFunctionHashes(self, programFile):
        funcsDict = {}
        service = FidService()
        logger().log('Function Hashes')
        funcMan = self.currentProgram.getFunctionManager()
        for func in funcMan.getFunctions(True):
            hf = service.hashFunction(func)
            if hf is None:
                continue
            logger().log('{} - {}'.format(func, hf))
            name = func.getName()
            if name in funcsDict:
                name = self.getUniqueName(funcsDict.keys(), name)
            funcsDict[name] = str(hf)
        funcsJson = json.dumps(funcsDict, indent=4)
        outfile = '{}.json'.format(programFile)
        with open(outfile, 'w') as jsonout:
            jsonout.write(funcsJson)

    def getUniqueName(self, keys, name):
        newname = name
        for i in range(100):
            newname = '{}_{:d}'.format(name, i)
            if newname not in keys:
                break
        return newname
