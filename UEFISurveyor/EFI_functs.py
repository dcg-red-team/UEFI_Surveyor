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

from artifacts import artifacts
from guids import convertGuidStr, guids
from ghidra_funcs import varnodeConverter, GhidraUtils
from hash import fnHashes

from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.address import AddressSpace
from ghidra.program.model.data import UnicodeDataType
from ghidra.program.model.listing import ParameterImpl
from ghidra.feature.fid.service import FidService
import ghidra.program.model.symbol.SourceType as SourceType


from uuid import UUID
import struct


class EFIUtils(GhidraUtils):
    # UEFI Specific functions needed for binary analysis
    def __init__(self, currentProgram):
        super(EFIUtils, self).__init__(currentProgram)

    def labelModuleEntryPoints(self, eps, isStandAloneMm=False):
        # update list of passed in addresses to ModuleEntryPoint
        dtm = self.currentProgram.getDataTypeManager()
        epType = dtm.getDataType("/UefiApplicationEntryPoint.h/functions/_ModuleEntryPoint")
        parameters = None
        if isStandAloneMm:
            parameterDefinitions = epType.getArguments()
            parameters = []
            for d in parameterDefinitions:
                if d.getName() == 'SystemTable':
                    mm_st = dtm.getDataType('/PiMMCis.h/EFI_MM_SYSTEM_TABLE *')
                    parameters.append(ParameterImpl(d.getName(), mm_st, self.currentProgram))
                else:
                    parameters.append(ParameterImpl(d.getName(), d.getDataType(), self.currentProgram))
        for index, entrypoint in enumerate(eps):
            self.updateFunctionDefinition(entrypoint, epType, "ModuleEntryPoint-{:d}".format(index), parameters)

    def findGlobalEfiPointers(self, func):
        # Identify instances of gST, gBS, EFI System Table, Image Handle
        hf = self.get_high_function(func)
        lPcodeOps = hf.getPcodeOps()
        while lPcodeOps.hasNext():
            var = lPcodeOps.next().getOutput()
            if var is not None and var.isAddress():
                varname = var.getHigh().getDataType().getName()
                if varname == "EFI_SYSTEM_TABLE *":
                    name = self.getNextLabel('gST')
                elif varname == "EFI_BOOT_SERVICES *":
                    name = self.getNextLabel('gBS')
                elif varname == "EFI_RUNTIME_SERVICES *":
                    name = self.getNextLabel('gRT')
                elif varname == "EFI_HANDLE":
                    name = self.getNextLabel('gImageHandle')
                elif varname == "EFI_MM_SYSTEM_TABLE *":
                    name = self.getNextLabel('gSmst')
                elif varname == "EFI_DXE_SERVICES *":
                    name = self.getNextLabel('gDS')
                else:
                    name = None
                if name is not None:
                    oAddr = self.toAddr(var.getOffset())
                    oDT = var.getHigh().getDataType()
                    if not artifacts().has_label(oAddr):
                        self.defineData(oAddr, oDT, name, None)
                        artifacts().add_label(oAddr, name, oDT)

    def identifyGBSProtocol(self, inFuncs=[]):
        # Identify and label protocols using gBS
        symbolName = "gBS"
        refs = self.getSymbolRefs(symbolName)
        refFuncs = self.getUniqueFuncts(refs)
        gbsFuncs = list(set(inFuncs + refFuncs))
        for func in gbsFuncs:
            hf = self.get_high_function(func)
            if hf is None:
                continue
            pcodeitr = hf.getPcodeOps()
            counter = 0
            while pcodeitr.hasNext():
                pcode = pcodeitr.next()
                if pcode.getOpcode() == PcodeOp.CALLIND:
                    if pcode.getInput(0).getHigh().getDataType().getName() == "EFI_LOCATE_PROTOCOL":
                        local = self.locateProtocol(pcode, 'gBS')
                        if local:
                            hfc = self.get_high_function(func)
                            pcodeitrCopy = hfc.getPcodeOps()
                            for i in range(counter):
                                if pcodeitrCopy.hasNext():
                                    pcodeitrCopy.next()
                                else:
                                    continue
                            self.propogateLocal(pcodeitrCopy, varnodeConverter(pcode.getInput(3)))
                    elif pcode.getInput(0).getHigh().getDataType().getName() == "EFI_INSTALL_PROTOCOL_INTERFACE":
                        self.installProtocol(pcode, 'gBS')
                counter += 1

    def identifySMST(self):
        # Identify and label SMST Instances
        # SMST must be identified after gBS
        symbolName = "gEFI_SMM_BASE2_PROTOCOL"
        symbolName = "gEFI_SMM_BASE2_PROTOCOL_GUID"
        symbolName2 = "EFI_SMM_BASE2_PROTOCOL_GUID"
        symbolName3 = "EFI_SMM_BASE2_PROTOCOL"
        refs = self.getSymbolRefs(symbolName)
        refs2 = self.getSymbolRefs(symbolName2, True)
        refs3 = self.getSymbolRefs(symbolName3)
        smstFuncs = self.getUniqueFuncts(refs + refs2 + refs3)
        for func in smstFuncs:
            hf = self.get_high_function(func)
            if hf is None:
                continue
            pcodeitr = hf.getPcodeOps()
            while pcodeitr.hasNext():
                pcode = pcodeitr.next()
                if pcode.getOpcode() == PcodeOp.CALLIND:
                    if pcode.getInput(0).getHigh().getDataType().getName() == "EFI_SMM_GET_SMST_LOCATION2":
                        if pcode.getNumInputs() - 1 == 2:
                            proto = pcode.getInput(2)
                            protoName = 'Smst'
                            #protoName = self.getNextLabel('Smst')
                            _, protoType = self.nameToProto("EFI_SMM_SYSTEM_TABLE2")
                            protoVar = varnodeConverter(proto)
                            self.labelvarNode(protoVar, protoName, protoType)

    def identifySMSTProtocol(self):
        # Identify and label protocols using SMST
        symbolName = "gSmst"
        refs = self.getSymbolRefs(symbolName)
        gbsFuncs = self.getUniqueFuncts(refs)
        for func in gbsFuncs:
            hf = self.get_high_function(func)
            if hf is None:
                continue
            pcodeitr = hf.getPcodeOps()
            while pcodeitr.hasNext():
                pcode = pcodeitr.next()
                if pcode.getOpcode() == PcodeOp.CALLIND:
                    if pcode.getInput(0).getHigh().getDataType().getName() == "EFI_LOCATE_PROTOCOL":
                        if pcode.getNumInputs() - 1 == 3:
                            self.locateProtocol(pcode, 'SMST')

    def identifySMSTHandlers(self):
        # Label Management Mode handlers
        toRegister = ["EFI_SMM_POWER_BUTTON_REGISTER2",
                      "EFI_SMM_SX_REGISTER2",
                      "EFI_SMM_SW_REGISTER2",
                      "EFI_SMM_PERIODIC_TIMER_REGISTER2",
                      "EFI_SMM_USB_REGISTER2",
                      "EFI_SMM_IO_TRAP_DISPATCH2_REGISTER",
                      "EFI_SMM_GPI_REGISTER2",
                      "EFI_MM_POWER_BUTTON_REGISTER",
                      "EFI_MM_STANDBY_BUTTON_REGISTER",
                      "EFI_MM_SX_REGISTER",
                      "EFI_MM_SW_REGISTER",
                      "EFI_MM_PERIODIC_TIMER_REGISTER",
                      "EFI_MM_USB_REGISTER",
                      "EFI_MM_IO_TRAP_DISPATCH_REGISTER",
                      "EFI_MM_GPI_REGISTER",]
        symbolName = "gSmst"
        refs = self.getSymbolRefs(symbolName)
        gbsFuncs = self.getUniqueFuncts(refs)
        for func in gbsFuncs:
            hf = self.get_high_function(func)
            if hf is None:
                continue
            pcodeitr = hf.getPcodeOps()
            counter = 0
            while pcodeitr.hasNext():
                pcode = pcodeitr.next()
                counter += 1
                if pcode.getOpcode() == PcodeOp.CALLIND:
                    if pcode.getInput(0).getHigh().getDataType().getName() in toRegister:
                        self.register2Handler(pcode, counter)
                    elif pcode.getInput(0).getHigh().getDataType().getName() in ["EFI_SMM_INTERRUPT_REGISTER", "EFI_MM_INTERRUPT_REGISTER"]:
                        self.register2Handler(pcode)
                        self.labelVarnodeGuid(varnodeConverter(pcode.getInput(pcode.getNumInputs()-2)))
                    elif pcode.getInput(0).getHigh().getDataType().getName() in ["EFI_SMM_REGISTER_PROTOCOL_NOTIFY", "EFI_MM_REGISTER_PROTOCOL_NOTIFY"]:
                        self.labelVarnodeGuid(varnodeConverter(pcode.getInput(pcode.getNumInputs()-3)))
                        self.registerNotify(pcode)
                    elif pcode.getInput(0).getHigh().getDataType().getName() == "EFI_INSTALL_PROTOCOL_INTERFACE":
                        self.installProtocol(pcode, 'SMST')

    def installProtocol(self, pcode, origin):
        # label the installed protocol
        # pcode - pcode instruction containing install protocol
        # origin - where the protocol is installed (SMST or gBS)
        dtm = self.currentProgram.getDataTypeManager()
        handle = pcode.getInput(1)
        handleVar = varnodeConverter(handle)
        handleName = 'handle'
        handleType = dtm.getDataType("/UefiBaseType.h/EFI_HANDLE *")
        self.labelvarNode(handleVar, handleName, handleType)
        # label the guid
        guid = pcode.getInput(2)
        guidVar = varnodeConverter(guid)
        guidName = self.labelVarnodeGuid(guidVar)
        # label the interface
        iface = pcode.getInput(4)
        ifaceVar = varnodeConverter(iface)
        if guidName is not None and ifaceVar.offset != 0:
            ifaceName, ifaceType = self.nameToProto(guidName, True)
            if ifaceName is None:
                ifaceName = "unknown_{}".format(guidName[:-5])
            self.labelvarNode(ifaceVar, ifaceName, ifaceType, origin)

    def locateProtocol(self, pcode, origin):
        # Label the protocol used in locateProtocol
        # pcode - pcode instruction containing install protocol
        # origin - where the protocol is installed (SMST or gBS)
        guid = pcode.getInput(1)
        guidVar = varnodeConverter(guid)
        guidName = self.labelVarnodeGuid(guidVar)
        if guidName is not None:
            proto = pcode.getInput(3)
            protoVar = varnodeConverter(proto)
            protoName = None
            protoType = None
            protoName, protoType = self.nameToProto(guidName, True)
            if protoName is None:
                # check to see if there is a non pointer version of the datatype
                protoName, protoType = self.nameToProto(guidName, True, False)
                if protoName is not None:
                    # check to see if already created
                    tmp, protoType = self.nameToProto(protoName, False)
                    if tmp:
                        protoName = tmp
                    else:
                        # Create a ptr version of the datatype
                        print('creating datatype')
                        if protoName.startswith('_'):
                            protoName = protoName[1:]
                        self.createDataType(protoName)
                        protoName, protoType = self.nameToProto(protoName, False)
                if protoType is None:
                    print('unable to find datatype')
                    dtm = self.currentProgram.getDataTypeManager()
                    protoName = "unknown_{}".format(guidName[:-5])
            self.labelvarNode(protoVar, protoName, protoType, origin)
            # if protoVar is local need to propogate locally
            if protoVar.isLocal():
                return True
        return False

    def propogateLocal(self, pcodeitr, lvarnode):
        # propogae a local variable name within the rest of a function
        # pcodeitr - pcode iterator for the rest of the pcode within a function
        # lvarnode - local varnode
        # @TODO, check if the location already has a name, if so don't rename
        while pcodeitr.hasNext():
            pcode = pcodeitr.next()
            for num in range(pcode.getNumInputs()):
                try:
                    if pcode.getOutput():
                        tmp = varnodeConverter(pcode.getOutput())
                        if lvarnode.offset == tmp.offset:
                            return
                    if lvarnode.offset == varnodeConverter(pcode.getInput(num)).offset:
                        if pcode.getOpcode() == PcodeOp.CALLIND:
                            return
                        if pcode.getOpcode() == PcodeOp.LOAD:
                            tmp = varnodeConverter(pcode.getOutput())
                            if tmp.isGlobal() and not artifacts().has_label(self.toAddr(tmp.offset)):
                                tmp.labelvarNode("fromGBS", None)
                        if pcode.getOpcode() == PcodeOp.COPY:
                            tmp = varnodeConverter(pcode.getOutput())
                            if tmp.isGlobal() and not artifacts().has_label(self.toAddr(tmp.offset)):
                                tmp.labelvarNode("fromGBS", None)
                        if pcode.getOpcode() == PcodeOp.INDIRECT:
                            tmp = varnodeConverter(pcode.getOutput())
                            if tmp.isGlobal() and not artifacts().has_label(self.toAddr(tmp.offset)):
                                tmp.labelvarNode("fromGBS", None)
                except Exception as e:
                    print('Unable to propgate local')
                    print(e)
                    continue

    def getContextValue(self, vnode, inpcode, counter):
        # Get the context value of the Handler registered with EFI_SMM_SW_REGISTER2/EFI_MM_SW_REGISTER
        # vnode - pcode instance
        # inpcode - pcode where instance is contained
        # counter - number of iterations to attempt looking for the context value
        ret = None
        func = vnode.getHigh().getHighFunction().getFunction()
        cvnode = varnodeConverter(vnode)
        hf = self.get_high_function(func)
        pcodeitr = hf.getPcodeOps()
        loop_cnt = counter if counter else 1000
        while pcodeitr.hasNext():
            pcode = pcodeitr.next()
            if pcode.getOpcode() == PcodeOp.COPY:
                if pcode.getOutput().getOffset() == cvnode.offset:
                    ret = pcode.getInput(0).getAddress().getOffset()
            if counter is None and pcode.getOpcode() == inpcode.getOpcode() and pcode.getInput(1).getAddress().getOffset() == inpcode.getInput(1).getAddress().getOffset():
                break
            if loop_cnt == 0:
                break
            loop_cnt -= 1
        return ret

    def register2Handler(self, pcode, counter=None):
        # Label SMI Handler
        # pcode - pcode instance of where handler is located
        # counter - number of iterations to attempt looking for context value
        dtm = self.currentProgram.getDataTypeManager()
        tname = pcode.getInput(0).getHigh().getDataType().getName()
        if pcode.getInput(0).getHigh().getDataType().getName() in ["EFI_SMM_SW_REGISTER2", "EFI_MM_SW_REGISTER"]:
            vnode = pcode.getInput(pcode.getNumInputs()-2)
            contextNumber = self.getContextValue(vnode, pcode, counter)
            if contextNumber is not None:
                fname = "swSmiHandler_{:x}".format(contextNumber)
            else:
                fname = "swSmiHandler_unknown"
        else:
            fname = self.getNextLabel("{}Handler".format(tname[8:-10].replace("_", "").replace("DISPATCH", "").lower()))
        vnode = varnodeConverter(pcode.getInput(pcode.getNumInputs()-3))
        faddr = self.toAddr(vnode.offset)
        fdef = dtm.getDataType("/PiMmCis.h/functions/EFI_MM_HANDLER_ENTRY_POINT")
        if vnode.isGlobal():
            self.updateFunctionDefinition(faddr, fdef, fname)

    def registerNotify(self, pcode):
        # Label SMI Notify Handler
        dtm = self.currentProgram.getDataTypeManager()
        fdef = dtm.getDataType("/PiMmCis.h/functions/EFI_MM_NOTIFY_FN")
        fname = self.getNextLabel("notifyHandler")
        vnode = varnodeConverter(pcode.getInput(pcode.getNumInputs()-2))
        faddr = self.toAddr(vnode.offset)
        if vnode.isGlobal():
            self.updateFunctionDefinition(faddr, fdef, fname)
            artifacts().add_notify(fname, artifacts().get_guid(self.toAddr(varnodeConverter(pcode.getInput(1)).offset))[0])

    def nameToProto(self, inName, isGuid=False, isPtr=True, TypeDefok=False):
        # Attempt to find a name within the datatypemanager
        # inName - Name to find
        # isGuid - is the Name a guid
        # isPtr - is the Name a pointer
        # TypeDefok - return typedef of name
        foundlist = []
        dtm = self.currentProgram.getDataTypeManager()
        if isGuid:
            tryName = inName[:-5]
        else:
            tryName = inName
        # attempt to find 4 variations _SMM_ -> _MM_ with * and without *
        if isPtr:
            dtm.findDataTypes("{} *".format(tryName.replace("_SMM_", "_MM_")), foundlist)
            dtm.findDataTypes("{} *".format(tryName), foundlist)
        else:
            dtm.findDataTypes("{}".format(tryName.replace("_SMM_", "_MM_")), foundlist)
            dtm.findDataTypes("{}".format(tryName), foundlist)
        if foundlist:
            if not TypeDefok and str(foundlist[0]).find('typedef') >= 0:
                if len(foundlist) == 1:
                    searchstr = "{}".format(str(foundlist[0]).split(' ')[2])
                    return self.nameToProto(searchstr, isPtr=isPtr)
                else:
                    return (tryName, foundlist[1])
            else:
                return (tryName, foundlist[0])
        else:
            return (None, None)

    def labelVarnodeGuid(self, guidVar):
        # label a GUID
        # guidVar - Varnode guid
        dtm = self.currentProgram.getDataTypeManager()
        varAddr = self.toAddr(guidVar.offset)
        guidName, _ = artifacts().get_guid(varAddr)
        if not artifacts().has_label(varAddr):
            if guidName is None:
                if guidVar.isGlobal():
                    try:
                        guidbytes = self.getBytes(varAddr, 16)
                        memGuid = UUID(bytes_le=struct.unpack('16s', guidbytes)[0])
                    except MemoryAccessException:
                        memGuid = UUID("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
                    guidName = "unknown_{}".format(str(memGuid)[:13])
                elif guidVar.isLocal():
                    guidName = self.getLocalGuidValue(guidVar)
            efiGuidType = dtm.getDataType("/UefiBaseType.h/EFI_GUID")
            self.labelvarNode(guidVar, guidName, efiGuidType)
        return guidName

    def getLocalGuidValue(self, guidVar):
        # Get the GUID value from a local variable
        # guidVar - VarNode that contains GUID
        guidList = []
        func = guidVar.varnode.getHigh().getHighFunction().getFunction()
        hf = self.get_high_function(func)
        pcodeitr = hf.getPcodeOps()
        while pcodeitr.hasNext():
            pcode = pcodeitr.next()
            if pcode.getOpcode() == PcodeOp.COPY:
                if pcode.getOutput().getOffset() in [guidVar.offset, guidVar.addr.add(4).getOffset(), guidVar.addr.add(8).getOffset(), guidVar.addr.add(12).getOffset()]:
                    guidList.append(pcode.getInput(0).getAddress().getOffset())
        guidstr = ""
        for i in guidList:
            guidstr += "{0:08X}".format(i)
        guidstr = convertGuidStr(guidstr)
        if len(guidstr) != 32:
            guidName = None
        else:
            try:
                guid = UUID(guidstr)
                guidName = guids().getGuidName(guid)
            except ValueError:
                guidName = None
        if guidName is None:
            guidName = "unknownGuid"
        return guidName

    def labelvarNode(self, node, name, dataType, origin=None):
        # label a varnode
        # node - node to label
        # datatype - what datatype to assign the node
        # origin - where the label originated
        if node.isGlobal():
            self._labelGlobalvarNode(node, name, dataType, origin)
        elif node.isLocal():
            self._labelLocalvarNode(node, name, dataType)
        else:
            print("unable to label unknown varnode address location")

    def _labelGlobalvarNode(self, node, name, dataType, origin):
        # label a  global varnode
        # node - node to label
        # datatype - what datatype to assign the node
        # origin - where the label originated
        varName = self.getNextLabel('g{}'.format(name))
        if not artifacts().has_protocol_global(self.toAddr(node.offset)):
            self.defineData(self.toAddr(node.offset), dataType, varName)
            artifacts().add_protocol_global(self.toAddr(node.offset), varName, dataType, origin)
        else:
            print("Address {} already has a label".format(node.addr))

    def _labelLocalvarNode(self, node, name, dataType):
        # label a local varnode
        # node - node to label
        # datatype - what datatype to assign the node
        varName = self.getNextLabel(name)
        func = node.varnode.getHigh().getHighFunction().getFunction()
        funcVars = func.getAllVariables()
        labelVar = None
        for variable in funcVars:
            if node.spaceId == AddressSpace.TYPE_REGISTER:
                if variable.isRegisterVariable() and variable.getRegister().getOffset() == node.addr:
                    labelVar = variable
                    break
            elif node.spaceId == AddressSpace.TYPE_VARIABLE:
                if variable.isStackVariable() and variable.getStackOffset() == node.offset:
                    labelVar = variable
                    break
        if labelVar is not None:
            node.defineVar(labelVar, dataType, varName)
            artifacts().add_protocol_local(func, labelVar, varName, dataType)

    def labelGuids(self):
        # search memory from minaddress to maxaddress looking for
        # potential guid matches
        dtm = self.currentProgram.getDataTypeManager()
        efiGuidType = dtm.getDataType("/UefiBaseType.h/EFI_GUID")

        start = self.currentProgram.getMinAddress()
        binSize = self.currentProgram.getMaxAddress().getOffset() - start.getOffset()

        for addrPlus in range(0, binSize, 4):
            addr = start.add(addrPlus)
            try:
                rawGuid = self.getBytes(addr, 16)
            except MemoryAccessException:
                continue
            memGuid = UUID(bytes_le=struct.unpack('16s', rawGuid)[0])
            if memGuid == UUID("00000000-0000-0000-0000-000000000000"):
                continue
            guidName = guids().getGuidName(memGuid)
            if guidName is not None:
                self.defineData(addr, efiGuidType, guidName, None)
                artifacts().add_guid(addr, guidName, memGuid)

    def functionVariableUse(self, func):
        """Return dictionary of GET_VARIABLE and SET_VARIABLE results within a function"""
        """SET_VARIABLE will return Name, GUID, size, and if the Data is concrete"""
        """GET_VARIBLE will return Name, GUID, and if the return value is checked"""
        # func - function to check
        hf = self.get_high_function(func)
        if hf is None:
            return {}
        pcodeitr = hf.getPcodeOps()
        res = {}
        counter = 0
        while pcodeitr.hasNext():
            pcode = pcodeitr.next()
            if pcode.getOpcode() == PcodeOp.CALLIND:
                tname = pcode.getInput(0).getHigh().getDataType().getName()
                if tname.find('ET_VARIABLE') > 0:
                    if tname not in res.keys():
                        res[tname] = []
                    nnode = varnodeConverter(pcode.getInput(1))
                    gnode = varnodeConverter(pcode.getInput(2))
                    gname = None
                    gguid = None
                    if nnode.isGlobal():
                        gname = self.getDataAt(self.toAddr(nnode.offset))
                    else:
                        gname = self.getContextValue(pcode.getInput(1), pcode, counter)
                        if gname is not None and not self.getDataAt(self.toAddr(gname)):
                            clearsize = self.findUnicodeSize(self.toAddr(gname))
                            if clearsize is not None:
                                listing = self.currentProgram.getListing()
                                listing.clearCodeUnits(self.toAddr(gname), self.toAddr(gname).add(clearsize), True)
                                self.createData(self.toAddr(gname), UnicodeDataType())
                        if gname is not None:
                            gname = self.getDataAt(self.toAddr(gname))
                    if gnode.isGlobal():
                        gguid = self.getSymbolAt(self.toAddr(gnode.offset))
                    else:
                        gguid = self.getLocalGuidValue(gnode)
                    if tname.find('SET_VARIABLE') > 0:
                        snode = varnodeConverter(pcode.getInput(4))
                        concreateSize = (pcode.getInput(4).getSpace() & AddressSpace.ID_TYPE_MASK) == AddressSpace.TYPE_CONSTANT
                        if snode.isGlobal():
                            ssize = snode.offset
                        else:
                            ssize = self.getContextValue(pcode.getInput(4), pcode, counter)
                        res[tname].append((gname, gguid, ssize, concreateSize))
                    elif tname.find('GET_VARIABLE') > 0:
                        rtchecked = False
                        if pcode.getOutput() is not None:
                            rnode = varnodeConverter(pcode.getOutput())
                            itercpy = hf.getPcodeOps()
                            for _ in range(counter+1):
                                itercpy.next()
                            rtchecked = self.returnChecked(itercpy, rnode)
                        res[tname].append((gname, gguid, rtchecked))
            counter += 1
        return res

    def findUnicodeSize(self, Addr):
        try:
            mbytes = self.getBytes(Addr, 64)
            for i in range(0, 63, 2):
                if mbytes[i] == 0 and mbytes[i + 1] == 0:
                    break
            return i + 1
        except MemoryAccessException:
            return None

    def returnChecked(self, pcodeitr, varnode):
        res = False
        while pcodeitr.hasNext():
            pcode = pcodeitr.next()
            if pcode.getOutput() and varnodeConverter(pcode.getOutput()).offset == varnode.offset:
                break
            for num in range(pcode.getNumInputs()):
                if varnode.offset == varnodeConverter(pcode.getInput(num)).offset:
                    if pcode.getOpcode() < 17 and pcode.getOpcode() > 10:
                        res = True
                        break
        return res

    def labelFnHashes(self):
        # Compare any hashes passed in by the user with the hashes in the file
        # if a match is found relabel the function with the user's function name
        mhash = fnHashes()
        service = FidService()
        funcMan = self.currentProgram.getFunctionManager()
        for func in funcMan.getFunctions(True):
            hf = service.hashFunction(func)
            newName = mhash.getFuncName(hf)
            if newName is not None:
                print('createfunction', newName, func.getEntryPoint())
                func.setName(newName, SourceType.USER_DEFINED)
                artifacts().add_function(func.getEntryPoint(), newName)
