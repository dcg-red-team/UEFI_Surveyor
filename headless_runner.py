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

from collections import namedtuple
from multiprocessing import Process, SimpleQueue
import os
import subprocess
import platform

from options import getGhidraOptions, loadOptions
from UEFISurveyor.logger import logger


Job = namedtuple("Job", ['task', 'filename'])

END_TASK = 0
PROCESS_FILE = 1


class progressBar:
    def __init__(self, size):
        self.size = size
        self.completed = 0

    def update(self, something=None):
        self.completed += 1
        self.printProgress()

    def printProgress(self):
        size = 100
        x = int(size * (self.completed / self.size))
        print(f"Progress [{'#'*x}{'.'*(size-x)}] {x}% {self.completed}/{self.size}")

    def complete(self):
        return self.completed == self.size


def getFileDetails(filename):
    machine = None
    dataType = None
    machineType = None
    with open(filename, 'rb') as f:
        data = f.read(0xfff)
        if b'VZ' in data:
            machine = data[2:4]
            dataType = 'TE'
        elif b'MZ' in data:
            dataType = 'PE'
            pe = data.find(b'PE')
            if pe > -1:
                machine = data[pe+4: pe+6]
    if machine:
        if machine == b'\x64\x86':
            machineType = '64bit'
        elif machine == b'\x4c\x01':
            machineType = '32bit'
    return (dataType, machineType)


def runHeadless(options, job, results, worker):
    ostype = platform.system()
    if ostype == 'Linux':
        gheadlesspath = os.path.join(options.ghidraPath, 'support', 'analyzeHeadless')
    elif ostype == 'Windows':
        gheadlesspath = os.path.join(options.ghidraPath, "support", "analyzeHeadless.bat")
    else:
        logger().log('Only supported on Windows and Linux at this time')
        return
    while True:
        injob = job.get()
        if injob.task == PROCESS_FILE:
            filename = injob.filename
            (dataType, machineType) = getFileDetails(filename)
            command = [gheadlesspath, options.ghidraProject, f'{options.projectName}{worker}', "-import", filename, "-overwrite"]
            command.append("-scriptPath")
            command.append(options.scriptPath)
            command.append("-preScript")
            command.append(os.path.join("UEFISurveyor", "analyze_pre.py"))
            if machineType == '64bit':
                command.append(options.gdtPath64)
            elif machineType == '32bit':
                command.append(options.gdtPath32)
            command.append("-postScript")
            command.append(os.path.join("UEFISurveyor", "analyze_post.py"))
            command.append(options.guidDBPath)
            command.append("-noanalysis")
            if dataType == 'TE':
                command.append('-processor')
                if machineType == '64bit':
                    command.append('x86:LE:64:default')
                elif machineType == '32bit':
                    command.append('x86:LE:32:default')
            command_txt = ' '.join(i for i in command)
            logger().log("About to execute {}".format(command_txt))
            res = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if 'Import failed for file' in str(res):
                logger().log(f'Unable to process {filename}')

            results.put(res)
        elif injob.task == END_TASK:
            break
        else:
            logger().log('Problem with the queue', injob.task)


if __name__ == "__main__":
    logger().enableStream()
    logger().log("Starting UEFI Surveyor")
    alloptions = loadOptions(os.path.join('UEFISurveyor', 'options.yaml'))
    options = getGhidraOptions(alloptions)
    proc_count = 4
    work = SimpleQueue()
    result = SimpleQueue()
    procs = []

    for i in range(proc_count):
        p = Process(target=runHeadless, args=(options, work, result, i))
        procs.append(p)
    for p in procs:
        p.start()

    pb = progressBar(len(os.listdir(options.efiPath)))
    pb.printProgress()

    filelist = os.listdir(options.efiPath)
    count = 0

    for _ in range(proc_count):
        if filelist:
            work.put(Job(PROCESS_FILE, os.path.join(options.efiPath, filelist.pop())))
        else:
            break
    while filelist:
        for count in range(proc_count):
            if filelist:
                work.put(Job(PROCESS_FILE, os.path.join(options.efiPath, filelist.pop())))
            else:
                break
        if count:
            for _ in range(count + 1):
                res = result.get()
                pb.update()

    while not pb.complete():
        res = result.get()
        pb.update()

    for p in procs:
        work.put(Job(END_TASK, None))

    for proc in procs:
        proc.join()

    logger().log("fin")
