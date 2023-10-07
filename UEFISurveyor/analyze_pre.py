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

from ghidra_funcs import loadGDTFile
import ghidra.util.Msg as Msg
from logger import logger
import sys

prefix_text = "[Pre]"


def output(text):
    logger().log('{} {}'.format(prefix_text, text))


if __name__ == "__main__":
    output("Welcome to the Analyse Pre Script")
    try:
        currentProgram.setImageBase(toAddr(0x80000000), True)
    except Exception as e:
        Msg.error("EFI Initialization", "Problems moving base address\n{}".format(e))

    # Set the write attribute on the .text section
    block = getMemoryBlock('.text')
    if block is not None:
        block.setWrite(True)

    # load gdt file
    args = getScriptArgs()
    output("Args passed in: {}".format(args))
    if len(args) > 0:
        gdtPath = args[0]
    else:
        logger().log('Missing Guid DB file!')
        sys.exit()

    output("Path is {}".format(gdtPath))

    loadGDTFile(gdtPath, currentProgram)
