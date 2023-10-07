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
# @category UEFISurveyor

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler.component import DecompilerUtils
import ghidra.util.Msg as Msg
from ghidra.program.disassemble import Disassembler
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.program.model.mem import MemoryAccessException

from ghidra_funcs import loadGDTFile
from logger import logger
from artifacts import artifacts
from guids import guids
from EFI_functs import EFIUtils
from analytics import EFIAnalytics

if __name__ == "__main__":
    logger().log("Attempting to Analyze EFI file")
    # Set Filenames for GUIDDB and GDT file
    guidFile = '/home/bh/devel/Demo/Tools/guidFinder/tmp_guid_db'
    gdtPath = '/home/bh/devel/Demo/Tools/prfGenerator/gdt_files/uefi_x64.gdt'

    # reset image base
    try:
        currentProgram.setImageBase(toAddr(0x80000000), True)
    except Exception as e:
        Msg.error("EFI Initialization", "Problems moving base address\n{}".format(e))

    # Set the write attribute on the .text section
    block = getMemoryBlock('.text')
    if block:
        block.setWrite(True)

    # load the definitions file
    loadGDTFile(gdtPath, currentProgram)

    # load the guid file
    guids().loadGuidFile(guidFile)

    # initialize GhidraUtils class
    EFIUtil = EFIUtils(currentProgram)
    EFIAnalytic = EFIAnalytics(currentProgram)

    #label Guids
    EFIUtil.labelGuids()

    # Search for Entry Points
    eps = EFIUtil.findModuleEntries()

    # ensure Decompiler Parameter ID is enabled
    setAnalysisOption(currentProgram, "Decompiler Parameter ID", "true")

    # Disassemble the entry points
    ctMon = ConsoleTaskMonitor()
    dis = Disassembler.getDisassembler(currentProgram, ctMon, None)
    for entry in eps:
        disAddrs = dis.disassemble(entry, None)
        AutoAnalysisManager.getAnalysisManager(currentProgram).codeDefined(disAddrs)
        AutoAnalysisManager.getAnalysisManager(currentProgram).waitForAnalysis(None, ctMon)

    # label entry points
    EFIUtil.labelModuleEntryPoints(eps)

    # propogate variables from entrypoint to find global tables
    propFuncs = []
    for entry in eps:
        entryFunc = getFunctionAt(entry)
        propFuncs += EFIUtil.propogateFunctionVariables(entryFunc, callonExit=EFIUtil.findGlobalEfiPointers)

    # label instances of locate protocol
    EFIUtil.identifyGBSProtocol(propFuncs)

    # label instances of SMST
    EFIUtil.identifySMST()

    # label insances where SMST uses locate protocol
    EFIUtil.identifySMSTProtocol()

    # label Management Mode handlers
    EFIUtil.identifySMSTHandlers()

    # log what is found
    artifacts().logArtifacts()

    # attempt to find callouts
    EFIAnalytic.identifyCallouts()

    # attempt to find TOCTOU instances
    EFIAnalytic.identifyTOCTOU()
