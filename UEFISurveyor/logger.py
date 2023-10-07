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
# @category UEFISurveyor.internal

import logging
import sys
import time


class Logger:
    """Class for logging to console, text file"""
    def __init__(self, name=None, stream=False):
        """The Constructor assign streamhandler."""
        self.logfile = None
        self.logstream = None
        self.rootLogger = logging.getLogger('{}{}'.format(__name__, str(time.time())))
        self.rootLogger.setLevel(logging.INFO)
        if stream:
            self.enableStream
        if name:
            self.enableLogFile(name)

    def enableStream(self):
        if self.logstream:
            self.closeStream
        self.logstream = logging.StreamHandler(sys.stdout)
        self.rootLogger.addHandler(self.logstream)

    def closeStream(self):
        if self.logstream:
            self.rootLogger.removeHandler(self.logstream)
            self.logstream.flush()
            self.logstream = None

    def enableLogFile(self, name):
        """Sets the log file for the output."""
        # Close filehandler if enabled then set a new filehandler
        if self.logfile:
            self.closeLogFile()

        if name:
            # Open new log file and keep it opened
            try:
                # creates FileHandler for log file
                self.logfile = logging.FileHandler(filename=name, mode='w')
                self.rootLogger.addHandler(self.logfile)  # adds filehandler to root logger

            except Exception:
                print("WARNING: Could not open log file enabling console output'{}'".format(name))
                self.enableStream()

    def closeLogFile(self):
        """Closes the log file."""
        if self.logfile:
            try:
                self.rootLogger.removeHandler(self.logfile)
                self.logfile.close()
            except Exception:
                print("WARNING: Could not close log file")
            finally:
                self.logfile = None

    def log(self, text):
        """Log message to rootlogger"""
        self.rootLogger.log(logging.INFO, text)


_logger = Logger()


def logger():
    return _logger
