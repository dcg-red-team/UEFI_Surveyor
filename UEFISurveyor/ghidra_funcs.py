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

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import ghidra.program.model.symbol.SourceType as SourceType
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing import ReturnParameterImpl
import ghidra.util.Msg as Msg
from ghidra.program.model.data import GenericCallingConvention
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.address import AddressSpace
import ghidra.program.flatapi.FlatProgramAPI as FlatAPI
import java.io.File as File
from ghidra.program.model.listing.Function import FunctionUpdateType
import ghidra.program.model.data.DataTypeConflictHandler as ConflictHandler
from ghidra.program.model.util import CodeUnitInsertionException

from artifacts import artifacts

import os
import struct


class GhidraUtils(FlatAPI):
    # Generic functions to expand GhidraAPIs for use within UEFISurveyor
    def __init__(self, currentProgram):
        super(GhidraUtils, self).__init__(currentProgram)

    def defineData(self, address, datatype=None, name=None, comment=None):
        # Defines data at an address
        # address - where to label the data
        # datatype - datatype to apply to address
        # name - label to apply to address
        # comment - comment to apply at address
        if address == self.toAddr(0):
            print("unable to DefineData at address 0")
            return False
        if datatype is not None:
            Msg.info("Defining Data", "Overwriting address {} with datatype {}".format(address, datatype))
            listing = self.currentProgram.getListing()
            clrLen = datatype.getLength() - 1
            if clrLen > 0:
                listing.clearCodeUnits(address, address.add(clrLen), True)
            try:
                self.createData(address, datatype)
            except CodeUnitInsertionException:
                pass
        if name is not None:
            self.createLabel(address, name, True, SourceType.USER_DEFINED)
        if comment is not None:
            self.setPlateComment(address, comment)
        return True

    def findModuleEntries(self):
        # Find module entry point of UEFI file
        # Note - if using individual files can rely on PE parsing and labeling
        entrypoints = []
        start = self.currentProgram.getMinAddress()
        maxAddr = self.currentProgram.getMaxAddress()
        # search for 'MZ' within loaded files
        mz_header = self.findBytes(start, 'MZ', 1)
        if mz_header and mz_header[0] == start:
            # search for 'PE' within 'MZ' entries
            for entry in mz_header:
                # check for 'PE'
                peHeader = self.findBytes(entry, 'PE', 1)
                if not peHeader:
                    continue
                peAddr = [i for i in peHeader][0]
                # @TODO verify this holds true in all cases
                if peAddr and peAddr.subtract(entry) < 0x100:
                    # Get EntryPoint address
                    ep = entry.add(struct.unpack('<I', self.getBytes(peAddr.add(0x28), 4))[0])
                    # Get Image Size
                    imageSize = entry.add(struct.unpack('<I', self.getBytes(peAddr.add(0x50), 4))[0])
                    # Sanity check to see if entrypoint is less than imageSize
                    if ep < imageSize and ep < maxAddr:
                        entrypoints.append(ep)
        # search for terse executable
        if not entrypoints:
            vz_header = self.findBytes(start, 'VZ', 100)
            for entry in vz_header:
                ep = entry.add(struct.unpack('<I', self.getBytes(entry.add(0x8), 4))[0])
                if ep < maxAddr:
                    entrypoints.append(ep)
        return entrypoints

    def propogateFunctionVariables(self, func, params=[], visited=[], callonExit=None):
        # propogae function variable to new functions
        # func - function to propogate variable from
        # params - specific parameters to propogate
        # visited - functions visited
        # callonExit - function to Call before exiting
        visited.append(func)
        hf = self.get_high_function(func)
        if hf is None:
            return visited
        hfProto = hf.getFunctionPrototype()
        ret = {}
        # for each param see if it's used in a call
        for i in range(hfProto.getNumParams()):
            hfParam = hfProto.getParam(i)
            paramName = hfParam.getName()
            if not params or paramName in params:
                paramLoc = hfParam.getStorage()
                paramDT = hfParam.getDataType()
                hv = hfParam.getHighVariable()
                varnode = hv.getRepresentative()
                fswo = DecompilerUtils.getForwardSliceToPCodeOps(varnode)
                for f in fswo:
                    if f.getOpcode() == PcodeOp.CALL:
                        toFunc = f.getInput(0).getAddress()
                        if toFunc in ret.keys():
                            ret[toFunc].append((paramName, paramLoc, paramDT))
                        else:
                            ret[toFunc] = [(paramName, paramLoc, paramDT)]
        # gather params
        for key in ret.keys():
            pFunc = self.getFunctionAt(key)
            if pFunc is None:
                continue
            params, funcDef = self.createParamList(pFunc, ret[key])
        # call change func definition
            self.updateFunctionDefinition(key, funcDef, pFunc.getName(), params)
        # call recursive for only params changed
            if pFunc not in visited:
                forwardparams = []
                for name, _, _ in ret[key]:
                    forwardparams.append(name)
                self.propogateFunctionVariables(pFunc, forwardparams, visited, callonExit)
        if callonExit is not None:
            callonExit(func)
        return visited

    def updateFunctionDefinition(self, funcAddr, funcDef, funcName=None, funcParams=None):
        # update a function definition
        # funcAddr - Address of function
        # funcDef - Original funciton definition
        # funcName - Name for function
        # funcParams - New function Parameters
        if funcAddr == self.toAddr(0):
            return False
        if funcParams is None:
            parameterDefinitions = funcDef.getArguments()
            parameters = []
            for d in parameterDefinitions:
                parameters.append(ParameterImpl(d.getName(), d.getDataType(), self.currentProgram))
        else:
            parameters = funcParams

        if funcName is None:
            funcName = funcDef.getName()
        returnType = ReturnParameterImpl(funcDef.getReturnType(), self.currentProgram)
        func = self.getFunctionAt(funcAddr)
        if func is None:
            func = self.createFunction(funcAddr, funcName)
            if func is None:
                Msg.error("updateFunction", "Unable to create function: {} at address{}".format(funcName, funcName))
        else:
            func.setName(funcName, SourceType.USER_DEFINED)
        if func is not None:
            if self.currentProgram.getMetadata().get('Address Size') == '64':
                func.updateFunction(GenericCallingConvention.fastcall.toString(), returnType, parameters, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, False, SourceType.USER_DEFINED)
            else:
                func.updateFunction(GenericCallingConvention.cdecl.toString(), returnType, parameters, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, False, SourceType.USER_DEFINED)
        artifacts().add_function(funcAddr, funcName)
        return True

    def get_markup_function(self, func):
        # get a function markup
        # func - function name
        options = DecompileOptions()
        monitor = ConsoleTaskMonitor()
        ifc = DecompInterface()
        ifc.setOptions(options)
        ifc.openProgram(self.currentProgram)
        res = ifc.decompileFunction(func, 60, monitor)
        tokenGroup = res.getCCodeMarkup()
        return tokenGroup

    def findDATinMarkup(self, tokenGroup):
        # Find DAT entries in Markup
        # tokenGroup - markup
        ret = set()
        tgString = tokenGroup.toString()
        loc = 0
        while loc != -1:
            loc = tgString.find('DAT_', loc)
            if loc != -1:
                ret.add(tgString[loc: loc+12])
                loc += 1
        return list(ret)

    def get_high_function(self, func):
        # Return Ghidra HighFunction class
        # func - function to decompile
        options = DecompileOptions()
        monitor = ConsoleTaskMonitor()
        ifc = DecompInterface()
        ifc.setOptions(options)
        ifc.openProgram(self.currentProgram)
        res = ifc.decompileFunction(func, 60, monitor)
        high = res.getHighFunction()
        return high

    def createParamList(self, func, changeParams):
        # Create a list of function parameters
        # func - function name
        # changeParams - Parameters to change from original
        outparams = []
        hf = self.get_high_function(func)
        hfProto = hf.getFunctionPrototype()
        for i in range(hfProto.getNumParams()):
            hfParam = hfProto.getParam(i)
            paramName = hfParam.getName()
            paramLoc = hfParam.getStorage()
            paramDT = hfParam.getDataType()
            for name, loc, DT in changeParams:
                if loc == paramLoc:
                    paramName = name
                    paramDT = DT
            outparams.append(ParameterImpl(paramName, paramDT, self.currentProgram))
        return (outparams, hfProto)

    def getSymbolRefs(self, symbolName, unique=False):
        """Return a list of references to a symbol"""
        # symbolName - symbol Name to get references of
        # unique - Attempt to find all references matching the name
        ret = []
        if unique:
            limit = 1
        else:
            limit = 100
        symbolTable = self.currentProgram.getSymbolTable()
        for index in range(limit):
            if not unique:
                newlabel = "{}_{:d}".format(symbolName, index)
            else:
                newlabel = symbolName
            found = [i for i in symbolTable.getSymbols(newlabel)]
            if found:
                for sym in found:
                    for ref in sym.getReferences():
                        refAddr = ref.getFromAddress()
                        if refAddr not in ret and refAddr is not None:
                            ret.append(refAddr)
            if not found:
                return ret
        return ret

    def getUniqueFuncts(self, addrlist):
        """Return a list of Unique functions from a list of Addresses"""
        # addrlist - list of addresses
        listing = self.currentProgram.getListing()
        ret = []
        for addr in addrlist:
            functionWithReference = listing.getFunctionContaining(addr)
            if functionWithReference not in ret and functionWithReference is not None:
                ret.append(functionWithReference)
        return ret

    def getNextLabel(self, label):
        """Generate Unique label from input"""
        # label - name of label
        symbolTable = self.currentProgram.getSymbolTable()
        index = 0
        while True:
            newlabel = "{}_{:d}".format(label, index)
            found = [i for i in symbolTable.getSymbols(newlabel)]
            if not found:
                return newlabel
            index += 1
            if index > 100:
                return label

    def isFunctionPath(self, start, goal, gSearchList=[], path=[]):
        """Return paths if a function can be reach a list of functions"""
        # start - initial function
        # goal - function to find a path into
        # gSearchList - functions searched
        # path - list of functions in path
        if not goal:
            return []
        if goal == start:
            path.append([start])
            return path
        if start not in gSearchList:
            gSearchList.append(start)
            for called in start.getCalledFunctions(self.getMonitor()):
                res = self.isFunctionPath(called, goal, gSearchList, [])
                if res:
                    for found in res:
                        found.append(start)
                        path.append(found)
        return path


class varnodeConverter(object):
    # class to hold varnode, address, AddressSpace type, and address offset
    # used to find and label individual elements within pcode
    def __init__(self, varnode):
        self.varnode = varnode
        self.addr, self.spaceId, self.offset = self.findvarNodeAddr()

    def findvarNodeAddr(self):
        # identify address, address space type and offset of a pcode element
        offset = self.varnode.getAddress().getOffset()
        addr = self.varnode.getAddress()
        retType = self.varnode.getSpace() & AddressSpace.ID_TYPE_MASK
        if self.varnode.isUnique():
            newvarNode = self.varnode.getDef()
            var0 = newvarNode.getInput(0)
            if var0.isUnique():
                var = varnodeConverter(var0)
                return var.findvarNodeAddr()
            if var0.isRegister():
                if var0.getAddress().getOffset() >= 0x20 and newvarNode.getNumInputs() > 1:
                    retType = AddressSpace.TYPE_VARIABLE
                    offset = newvarNode.getInput(1).getAddress().getOffset()
                    addr = newvarNode.getInput(1).getAddress()
                elif var0.getAddress().getOffset() >= 0x20:
                    retType = AddressSpace.TYPE_VARIABLE
                    addr = var0.getAddress()
                    offset = var0.getAddress().getOffset()
                else:
                    retType = var0.getSpace() & AddressSpace.ID_TYPE_MASK
                    addr = var0.getAddress()
                    offset = var0.getAddress().getOffset()
            elif var0.isConstant():
                var1 = newvarNode.getInput(1)
                if var1 is not None:
                    retType = var1.getSpace() & AddressSpace.ID_TYPE_MASK
                    offset = var1.getAddress().getOffset()
                    addr = var1.getAddress()
                else:
                    retType = var0.getSpace() & AddressSpace.ID_TYPE_MASK
                    offset = var0.getAddress().getOffset()
                    addr = var0.getAddress()
        return addr, retType, offset

    def isGlobal(self):
        """return whether varnode is global to function"""
        if self.spaceId in [AddressSpace.TYPE_CONSTANT, AddressSpace.TYPE_RAM]:
            return True
        return False

    def isLocal(self):
        """return whether varnode is local to function"""
        if self.spaceId in [AddressSpace.TYPE_REGISTER, AddressSpace.TYPE_VARIABLE]:
            return True
        return False

    def defineVar(self, var, dataType=None, name=None):
        """Set a new Name or dataType for a variable"""
        if name is not None:
            var.setName(name, SourceType.USER_DEFINED)
        if dataType is not None:
            var.setDataType(dataType, False, True, SourceType.USER_DEFINED)


def loadGDTFile(gdtPath, currentProgram):
    mflatAPI = FlatAPI(currentProgram)
    dtm = currentProgram.getDataTypeManager()
    gdtFile = File(gdtPath)
    newDTM = mflatAPI.openDataTypeArchive(gdtFile, True)
    dtl = []
    newDTM.getAllDataTypes(dtl)
    kh = ConflictHandler.KEEP_HANDLER
    dtm.addDataTypes(dtl, kh, ConsoleTaskMonitor())
