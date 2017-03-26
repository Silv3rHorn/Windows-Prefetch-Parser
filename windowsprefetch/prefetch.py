#!/usr/bin/python

# Copyright 2015 Adam Witt
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Contact: <accidentalassist@gmail.com>



from argparse import ArgumentParser
import binascii
import ctypes
from datetime import datetime,timedelta
import ntpath
import os
import struct
import sys
import tempfile
import sqlite3

class Prefetch(object):
    class PfFileMetric(object):
        def __init__(self, traceRecord=0, traceRecordCount=0, fetchCount=0, pathOffset=0, pathLength=0, flags=0, mftRecNum=0, mftRecSeq=0):
            self.TraceRecord = traceRecord
            self.TraceRecordCount = traceRecordCount
            self.FetchCount = fetchCount
            self.PathOffset = pathOffset
            self.PathLength = pathLength
            self.Flags = flags
            self.MftRecNum = mftRecNum
            self.MftRecSeq = mftRecSeq
            self.PathArrayId = -1

        def GetFileProps(self):
            retval = ""
            if self.Flags & 0x0200:
                retval += "X"
            else:
                retval += "."
            if self.Flags & 0x0002:
                retval += "R"
            else:
                retval += "."
            if self.Flags & 0x0001:
                retval += "D"
            else:
                retval += "."
            return retval

    def GetTraceUsage(self, str):
        for i in self.FileMetricArray:
            if i.PathArrayId == self.resources.index(str):
                arr = self.TraceChainArray[i.TraceRecord:i.TraceRecord+i.TraceRecordCount]
                retval = 0
                for j in arr:
                    retval |= j.Used
                #arr = 0
                return format(retval, "08b")

    def GetTraceFetchage(self, str):
        for i in self.FileMetricArray:
            if i.PathArrayId == self.resources.index(str):
                arr = self.TraceChainArray[i.TraceRecord:i.TraceRecord + i.TraceRecordCount]
                retval = 0
                for j in arr:
                    retval |= j.Fetched
                # arr = 0
                return format(retval, "08b")

    def GetFileProps(self, str):
        for i in self.FileMetricArray:
            if i.PathArrayId == self.resources.index(str):
                return i.GetFileProps()

    class PfTraceChain(object):
        def __init__(self, recordNum=0, nextRecordNum=0, memPage=0, flag1=0, flag2=0, used=0, fetched=0):
            self.RecordNum = recordNum
            self.NextRecordNum = nextRecordNum
            self.MemPage = memPage
            self.Flag1 = flag1
            self.Flag2 = flag2
            self.Used = used
            self.Fetched = fetched

        def GetFlag1Props(self):
            retval = ""
            if self.Flag1 & 0x02:
                retval += "X"
            else:
                retval += "."
            if self.Flag1 & 0x04:
                retval += "R"
            else:
                retval += "."
            if self.Flag1 & 0x08:
                retval += "F"
            else:
                retval += "."
            if self.Flag1 & 0x01:
                retval += "D"
            else:
                retval += "."
            return retval

        def UsedString(self):
            return format(self.Used, "08b")

        def FetchedString(self):
            return format(self.Fetched, "08b")

    #class PfFilePath(object):
    #    def __init__(self, filePath="", offset=0):
    #        self.FilePath = filePath
    #        self.Offset = offset

#class Prefetch(object):
    def __init__(self, infile):
        self.pFileName = infile
        self.FileMetricArray = []
        self.TraceChainArray = []
        self.resources = []

        with open(infile, "rb") as f:
            if f.read(3) == "MAM":
                f.close()

                d = DecompressWin10()
                decompressed = d.decompress(infile)

                t = tempfile.mkstemp()

                with open(t[1], "wb+") as f:
                    f.write(decompressed)
                    f.seek(0)

                    self.parseHeader(f)
                    self.fileInformation26(f)
                    self.metricsArray23(f)
                    self.traceChainsArray30(f)
                    self.volumeInformation30(f)
                    self.getTimeStamps(self.lastRunTime)
                    self.directoryStrings(f)
                    self.getFilenameStrings(f)
                    return

        with open(infile, "rb") as f:
            self.parseHeader(f)
            
            if self.version == 17:
                self.fileInformation17(f)
                self.metricsArray17(f)
                self.traceChainsArray17(f)
                self.volumeInformation17(f)
                self.getTimeStamps(self.lastRunTime)
                self.directoryStrings(f)
            
            elif self.version == 23:
                self.fileInformation23(f)
                self.metricsArray23(f)
                self.traceChainsArray17(f)
                self.volumeInformation23(f)
                self.getTimeStamps(self.lastRunTime)
                self.directoryStrings(f)

            elif self.version == 26:
                self.fileInformation26(f)
                self.metricsArray23(f)
                self.traceChainsArray17(f)
                self.volumeInformation23(f)
                self.getTimeStamps(self.lastRunTime)
                self.directoryStrings(f)

            self.getFilenameStrings(f)

    def parseHeader(self, infile):
        # Parse the file header
        # 84 bytes
        self.version = struct.unpack_from("I", infile.read(4))[0]
        self.signature = struct.unpack_from("I", infile.read(4))[0]
        unknown0 = struct.unpack_from("I", infile.read(4))[0]
        self.fileSize = struct.unpack_from("I", infile.read(4))[0]
        executableName = struct.unpack_from("60s", infile.read(60))[0]
        executableName = executableName.split("\x00\x00")[0]
        self.executableName = executableName.replace("\x00", "")
        rawhash = hex(struct.unpack_from("I", infile.read(4))[0])
        self.hash = rawhash.lstrip("0x")

        unknown1 = infile.read(4)

    def fileInformation17(self, infile):
        # File Information
        # 68 bytes
        self.metricsOffset = struct.unpack_from("I", infile.read(4))[0]
        self.metricsCount = struct.unpack_from("I", infile.read(4))[0]
        self.traceChainsOffset = struct.unpack_from("I", infile.read(4))[0]
        self.traceChainsCount = struct.unpack_from("I", infile.read(4))[0]
        self.filenameStringsOffset = struct.unpack_from("I", infile.read(4))[0]
        self.filenameStringsSize = struct.unpack_from("I", infile.read(4))[0]
        self.volumesInformationOffset = struct.unpack_from("I", infile.read(4))[0]
        self.volumesCount = struct.unpack_from("I", infile.read(4))[0]
        self.volumesInformationSize = struct.unpack_from("I", infile.read(4))[0]
        self.lastRunTime = infile.read(8)
        unknown0 = infile.read(16)
        self.runCount = struct.unpack_from("I", infile.read(4))[0]
        unknown1 = infile.read(4)

    def metricsArray17(self, infile):
        # File Metrics Array
        # 20 bytes
        infile.seek(self.metricsOffset)
        count = 0

        while count < self.metricsCount:
            record = Prefetch.PfFileMetric()
            record.TraceRecord = struct.unpack_from("I", infile.read(4))[0]
            record.TraceRecordCount = struct.unpack_from("I", infile.read(4))[0]
            record.PathOffset = struct.unpack_from("I", infile.read(4))[0]
            record.PathLength = struct.unpack_from("I", infile.read(4))[0]
            record.Flags = struct.unpack_from("I", infile.read(4))[0]
            self.FileMetricArray.append(record)
            count += 1

    def traceChainsArray17(self, infile):
        # Read through the Trace Chains Array
        # Not being parsed for information
        # 12 bytes
        infile.seek(self.traceChainsOffset)
        count = 0

        while count < self.traceChainsCount:
            record = Prefetch.PfTraceChain()
            record.RecordNum = count
            record.NextRecordNum = struct.unpack_from("<i", infile.read(4))[0]
            record.MemPage = struct.unpack_from("<I", infile.read(4))[0]
            record.Flag1 = struct.unpack_from("B", infile.read(1))[0]
            record.Flag2 = struct.unpack_from("B", infile.read(1))[0]
            record.Used = struct.unpack_from("B", infile.read(1))[0]
            record.Fetched = struct.unpack_from("B", infile.read(1))[0]

            self.TraceChainArray.append(record)
            count += 1

    def volumeInformation17(self, infile):
        # Volume information
        # 40 bytes per entry in the array
        
        infile.seek(self.volumesInformationOffset)
        self.volumesInformationArray = []
        self.directoryStringsArray = []
        count = 0
        
        while count < self.volumesCount:
            self.volPathOffset = struct.unpack_from("I", infile.read(4))[0]
            self.volPathLength = struct.unpack_from("I", infile.read(4))[0]
            self.volCreationTime = struct.unpack_from("Q", infile.read(8))[0]
            self.volSerialNumber = hex(struct.unpack_from("I", infile.read(4))[0])
            self.volSerialNumber = self.volSerialNumber.rstrip("L").lstrip("0x")
            self.fileRefOffset = struct.unpack_from("I", infile.read(4))[0]
            self.fileRefSize = struct.unpack_from("I", infile.read(4))[0]
            self.dirStringsOffset = struct.unpack_from("I", infile.read(4))[0]
            self.dirStringsCount = struct.unpack_from("I", infile.read(4))[0]
            unknown0 = infile.read(4)

            self.directoryStringsArray.append(self.directoryStrings(infile))

            infile.seek(self.volumesInformationOffset + self.volPathOffset)
            volume = {}
            volume["Volume Name"] = infile.read(self.volPathLength * 2).replace("\x00", "")
            volume["Creation Date"] = self.convertTimestamp(self.volCreationTime)
            volume["Serial Number"] = self.volSerialNumber
            self.volumesInformationArray.append(volume)
            
            count += 1
            infile.seek(self.volumesInformationOffset + (40 * count))

    def fileInformation23(self, infile):
        # File Information
        # 156 bytes
        self.metricsOffset = struct.unpack_from("I", infile.read(4))[0]
        self.metricsCount = struct.unpack_from("I", infile.read(4))[0]
        self.traceChainsOffset = struct.unpack_from("I", infile.read(4))[0]
        self.traceChainsCount = struct.unpack_from("I", infile.read(4))[0]
        self.filenameStringsOffset = struct.unpack_from("I", infile.read(4))[0]
        self.filenameStringsSize = struct.unpack_from("I", infile.read(4))[0]
        self.volumesInformationOffset = struct.unpack_from("I", infile.read(4))[0]
        self.volumesCount = struct.unpack_from("I", infile.read(4))[0]
        self.volumesInformationSize = struct.unpack_from("I", infile.read(4))[0]
        unknown0 = infile.read(8)
        self.lastRunTime = infile.read(8)
        unknown1 = infile.read(16)
        self.runCount = struct.unpack_from("I", infile.read(4))[0]
        unknown2 = infile.read(84)

    def metricsArray23(self, infile):
        # File Metrics Array
        # 32 bytes per array, not parsed in this script
        #infile.seek(self.metricsOffset)

        infile.seek(self.metricsOffset)
        count = 0

        while count < self.metricsCount:
            record = Prefetch.PfFileMetric()
            record.TraceRecord = struct.unpack_from("<I", infile.read(4))[0]
            record.TraceRecordCount = struct.unpack_from("<I", infile.read(4))[0]
            record.FetchCount = struct.unpack_from("<I", infile.read(4))[0]
            record.PathOffset = struct.unpack_from("<I", infile.read(4))[0]
            record.PathLength = struct.unpack_from("<I", infile.read(4))[0]
            record.Flags = struct.unpack_from("<I", infile.read(4))[0]

            record.MftRecNum = struct.unpack_from("<I", infile.read(6))[0]
            #self.convertFileReference(infile.read(6))
            record.MftRecSeq = struct.unpack_from("<H", infile.read(2))[0]

            self.FileMetricArray.append(record)
            count += 1

    def volumeInformation23(self, infile):
        # This function consumes the Volume Information array
        # 104 bytes per structure in the array
        # Returns a dictionary object which holds another dictionary
        # for each volume information array entry

        infile.seek(self.volumesInformationOffset)
        self.volumesInformationArray = []
        self.directoryStringsArray = []
        
        count = 0
        while count < self.volumesCount:
            self.volPathOffset = struct.unpack_from("I", infile.read(4))[0]
            self.volPathLength = struct.unpack_from("I", infile.read(4))[0]
            self.volCreationTime = struct.unpack_from("Q", infile.read(8))[0]
            volSerialNumber = hex(struct.unpack_from("I", infile.read(4))[0])
            self.volSerialNumber = volSerialNumber.rstrip("L").lstrip("0x")
            self.fileRefOffset = struct.unpack_from("I", infile.read(4))[0]
            self.fileRefCount = struct.unpack_from("I", infile.read(4))[0]
            self.dirStringsOffset = struct.unpack_from("I", infile.read(4))[0]
            self.dirStringsCount = struct.unpack_from("I", infile.read(4))[0]
            unknown0 = infile.read(68)

            self.directoryStringsArray.append(self.directoryStrings(infile))
            
            infile.seek(self.volumesInformationOffset + self.volPathOffset)
            volume = {}
            volume["Volume Name"] = infile.read(self.volPathLength * 2).replace("\x00", "")
            volume["Creation Date"] = self.convertTimestamp(self.volCreationTime)
            volume["Serial Number"] = self.volSerialNumber
            self.volumesInformationArray.append(volume)
            
            count += 1
            infile.seek(self.volumesInformationOffset + (104 * count))


    def fileInformation26(self, infile):
        # File Information
        # 224 bytes
        self.metricsOffset = struct.unpack_from("I", infile.read(4))[0]
        self.metricsCount = struct.unpack_from("I", infile.read(4))[0]
        self.traceChainsOffset = struct.unpack_from("I", infile.read(4))[0]
        self.traceChainsCount = struct.unpack_from("I", infile.read(4))[0]
        self.filenameStringsOffset = struct.unpack_from("I", infile.read(4))[0]
        self.filenameStringsSize = struct.unpack_from("I", infile.read(4))[0]
        self.volumesInformationOffset = struct.unpack_from("I", infile.read(4))[0]
        self.volumesCount = struct.unpack_from("I", infile.read(4))[0]
        self.volumesInformationSize = struct.unpack_from("I", infile.read(4))[0]
        unknown0 = infile.read(8)
        self.lastRunTime = infile.read(64)
        unknown1 = infile.read(16)
        self.runCount = struct.unpack_from("I", infile.read(4))[0]
        unknown2 = infile.read(96)

    #def traceChainsArray30(self, infile):
        # Trace Chains Array
        # same format


    def volumeInformation30(self, infile):
        # Volumes Information
        # 96 bytes

        infile.seek(self.volumesInformationOffset)
        self.volumesInformationArray = []
        self.directoryStringsArray = []

        count = 0
        while count < self.volumesCount:
            self.volPathOffset = struct.unpack_from("I", infile.read(4))[0] 
            self.volPathLength = struct.unpack_from("I", infile.read(4))[0]
            self.volCreationTime = struct.unpack_from("Q", infile.read(8))[0]
            self.volSerialNumber = hex(struct.unpack_from("I", infile.read(4))[0])
            self.volSerialNumber = self.volSerialNumber.rstrip("L").lstrip("0x")
            self.fileRefOffset = struct.unpack_from("I", infile.read(4))[0]
            self.fileRefCount = struct.unpack_from("I", infile.read(4))[0]
            self.dirStringsOffset = struct.unpack_from("I", infile.read(4))[0]
            self.dirStringsCount = struct.unpack_from("I", infile.read(4))[0]
            unknown0 = infile.read(60)

            self.directoryStringsArray.append(self.directoryStrings(infile))

            infile.seek(self.volumesInformationOffset + self.volPathOffset)
            volume = {}
            volume["Volume Name"] = infile.read(self.volPathLength * 2).replace("\x00", "")
            volume["Creation Date"] = self.convertTimestamp(self.volCreationTime)
            volume["Serial Number"] = self.volSerialNumber
            self.volumesInformationArray.append(volume)
            
            count += 1
            infile.seek(self.volumesInformationOffset + (96 * count))



    def getFilenameStrings(self, infile):
        # Parses filename strings from the PF file
        #self.resources = []
        infile.seek(self.filenameStringsOffset)
        #record = PfFilePath()

        self.filenames = infile.read(self.filenameStringsSize).decode("utf16").encode("utf8")

        for i in self.filenames.split("\x00"):
            self.resources.append(i)

        for i in self.FileMetricArray:
            infile.seek(self.filenameStringsOffset + i.PathOffset)
            path = infile.read(i.PathLength*2).decode("utf16").encode("utf8")
            for j in self.resources:
                if j == path:
                    i.PathArrayId = self.resources.index(j)
                    break

    def convertTimestamp(self, timestamp):
        # Timestamp is a Win32 FILETIME value
        # This function returns that value in a human-readable format
        return str(datetime(1601,1,1) + timedelta(microseconds=timestamp / 10.))


    def getTimeStamps(self, lastRunTime):
        self.timestamps = []

        start = 0
        end = 8
        while end <= len(lastRunTime):
            timestamp = struct.unpack_from("Q", lastRunTime[start:end])[0]

            if timestamp:
                self.timestamps.append(self.convertTimestamp(timestamp))
                start += 8
                end += 8
            else:
                break

    def directoryStrings(self, infile):
        infile.seek(self.volumesInformationOffset)
        infile.seek(self.dirStringsOffset, 1)

        directoryStrings = []

        count = 0
        while count < self.dirStringsCount:
            stringLength = struct.unpack_from("<H", infile.read(2))[0] * 2
            directoryString = infile.read(stringLength).replace("\x00", "")
            infile.read(2) # Read through the end-of-string null byte
            directoryStrings.append(directoryString)
            count += 1

        return directoryStrings

    def convertFileReference(self, buf):
        byteArray = map(lambda x: '%02x' % ord(x), buf)
            
        byteString = ""
        for i in byteArray[::-1]:
            byteString += i
        
        return int(byteString, 16)


    def prettyPrint(self, verbose):
        # Prints important Prefetch data in a structured format
        banner = "=" * (len(ntpath.basename(self.pFileName)) + 2)
        print "\n{0}\n{1}\n{0}\n".format(banner, ntpath.basename(self.pFileName))
        print "Executable Name: {}\n".format(self.executableName)
        print "Run count: {}".format(self.runCount)

        if len(self.timestamps) > 1:
            print "Last Executed:"
            for i in self.timestamps:
                print "    " + i
        else:
            print "Last Executed: {}".format(self.timestamps[0])
        
        print "\nVolume Information:"
        for i in self.volumesInformationArray:
            print "    Volume Name: " + i["Volume Name"]
            print "    Creation Date: " + i["Creation Date"]
            print "    Serial Number: " + i["Serial Number"]
            print ""

        print "Directory Strings:"
        for volume in self.directoryStringsArray:
            for i in volume:
                print "    " + i
        print ""

        print "Resources loaded:\n"
        print "       Used     Fetched  Props Path"
        print "       87654321 87654321"
        count = 1
        for i in self.resources:
            if i:
                #print "{:5}: {}".format(count, i)
                print "{:5}: {} {} {}    {}".format(count, self.GetTraceUsage(i), self.GetTraceFetchage(i), self.GetFileProps(i), i)

                #if count > 999:
                #    print "{}: {}".format(count, i)
                #if count > 99:
                #    print "{}:  {}".format(count, i)
                #elif count > 9:
                #    print "{}:   {}".format(count, i)
                #else:
                #    print "{}:    {}".format(count, i)
            count += 1

        print ""
        if verbose:
            print "Section A offset: " + str(self.metricsOffset)
            print "Section A count: " + str(self.metricsCount)
            print "Section B offset: " + str(self.traceChainsOffset)
            print "Section B count: " + str(self.traceChainsCount)
            print "Section C offset: " + str(self.filenameStringsOffset)
            print "Section C size: " + str(self.filenameStringsSize)
            print "Section C count: " + str(self.resources.__len__())
            print ""

            print "Section A Records (File Metrics)"
            print "TraceRec Count PfCnt PthOff PthLen Flags     MftRec Seq  Path"
            for rec in self.FileMetricArray:
                print "{:8} {:5} {:5} {:6} {:6} x{:04x}-{} {:7} {:3}  {}".format(rec.TraceRecord, rec.TraceRecordCount, rec.FetchCount, rec.PathOffset, rec.PathLength, rec.Flags,
                                                          rec.GetFileProps(), rec.MftRecNum, rec.MftRecSeq, self.resources[rec.PathArrayId])
            print ""

            print "Section B Records (Trace Chains)"
            print "RecNum NextRec  MemPg    Flag1     Flg2 Used     Fetched"
            nameFlop = 1
            for trace in self.TraceChainArray:
                if nameFlop:
                    fileString = self.resources[filter(lambda x: x.TraceRecord==trace.RecordNum, self.FileMetricArray)[0].PathArrayId]
                    nameFlop = 0
                if trace.NextRecordNum == -1:
                    nameFlop = 1
                print "{:6}  {:6} {:6} {:08b}-{}    {} {:08b} {:08b} {}".format(trace.RecordNum, trace.NextRecordNum, trace.MemPage, trace.Flag1, trace.GetFlag1Props(),
                                                                                trace.Flag2, trace.Used, trace.Fetched, fileString)
                fileString = ""


    def sqliteOutput(self):
        global conn
        global cur

        cur.execute('insert into headers values (?,?,?,?)', [ntpath.basename(self.pFileName),self.executableName,self.runCount,self.timestamps[0]])

        for volume in self.directoryStringsArray:
            for i in volume:
                cur.execute('insert into dirs values (?,?)',[ntpath.basename(self.pFileName),i])

        for i in self.resources:
            if i:
                cur.execute('insert into files values (?,?)',[ntpath.basename(self.pFileName), i])

        conn.commit()


# The code in the class below was taken and then modified from Francesco 
# Picasso's w10pfdecomp.py script. This modification makes two simple changes:
#
#    - Wraps Francesco's logic in a Python class 
#    - Returns a bytearray of uncompressed data instead of writing it to a new 
#      file, like Francesco's original code did
#
# Author's name: Francesco "dfirfpi" Picasso
# Author's email: francesco.picasso@gmail.com
# Source: https://github.com/dfirfpi/hotoloti/blob/master/sas/w10pfdecomp.py
# License: http://www.apache.org/licenses/LICENSE-2.0

#Windows-only utility to decompress MAM compressed files
class DecompressWin10(object):
    def __init__(self):
        pass

    def tohex(self, val, nbits):
        """Utility to convert (signed) integer to hex."""
        return hex((val + (1 << nbits)) % (1 << nbits))

    def decompress(self, infile):
        """Utility core."""

        NULL = ctypes.POINTER(ctypes.c_uint)()
        SIZE_T = ctypes.c_uint
        DWORD = ctypes.c_uint32
        USHORT = ctypes.c_uint16
        UCHAR  = ctypes.c_ubyte
        ULONG = ctypes.c_uint32

        # You must have at least Windows 8, or it should fail.
        try:
            RtlDecompressBufferEx = ctypes.windll.ntdll.RtlDecompressBufferEx
        except AttributeError, e:
            sys.exit("[ - ] {}".format(e) + \
            "\n[ - ] Windows 8+ required for this script to decompress Win10 Prefetch files")

        RtlGetCompressionWorkSpaceSize = \
            ctypes.windll.ntdll.RtlGetCompressionWorkSpaceSize

        with open(infile, 'rb') as fin:
            header = fin.read(8)
            compressed = fin.read()

            signature, decompressed_size = struct.unpack('<LL', header)
            calgo = (signature & 0x0F000000) >> 24
            crcck = (signature & 0xF0000000) >> 28
            magic = signature & 0x00FFFFFF
            if magic != 0x004d414d :
                sys.exit('Wrong signature... wrong file?')

            if crcck:
                # I could have used RtlComputeCrc32.
                file_crc = struct.unpack('<L', compressed[:4])[0]
                crc = binascii.crc32(header)
                crc = binascii.crc32(struct.pack('<L',0), crc)
                compressed = compressed[4:]
                crc = binascii.crc32(compressed, crc)          
                if crc != file_crc:
                    sys.exit('{} Wrong file CRC {0:x} - {1:x}!'.format(infile, crc, file_crc))

            compressed_size = len(compressed)

            ntCompressBufferWorkSpaceSize = ULONG()
            ntCompressFragmentWorkSpaceSize = ULONG()

            ntstatus = RtlGetCompressionWorkSpaceSize(USHORT(calgo),
                ctypes.byref(ntCompressBufferWorkSpaceSize),
                ctypes.byref(ntCompressFragmentWorkSpaceSize))

            if ntstatus:
                sys.exit('Cannot get workspace size, err: {}'.format(
                    self.tohex(ntstatus, 32)))
                    
            ntCompressed = (UCHAR * compressed_size).from_buffer_copy(compressed)
            ntDecompressed = (UCHAR * decompressed_size)()
            ntFinalUncompressedSize = ULONG()
            ntWorkspace = (UCHAR * ntCompressFragmentWorkSpaceSize.value)()
            
            ntstatus = RtlDecompressBufferEx(
                USHORT(calgo),
                ctypes.byref(ntDecompressed),
                ULONG(decompressed_size),
                ctypes.byref(ntCompressed),
                ULONG(compressed_size),
                ctypes.byref(ntFinalUncompressedSize),
                ctypes.byref(ntWorkspace))

            if ntstatus:
                sys.exit('Decompression failed, err: {}'.format(
                    self.tohex(ntstatus, 32)))

            if ntFinalUncompressedSize.value != decompressed_size:
                sys.exit('Decompressed with a different size than original!')

        return bytearray(ntDecompressed)


def createSqlite():
    try:
        global conn
        global cur
        #conn = sqlite3.connect(path)
        #self.cur = self.conn.cursor()

        cur.execute('create table if not exists headers (filename text,exename text,runcount text,lastrun text)')
        cur.execute('create table if not exists dirs (filename text,dirname text)')
        cur.execute('create table if not exists files (filename text,filepath text)')

        cur.execute('CREATE INDEX if not exists [headers_idx1] ON headers (filename,exename);')
        cur.execute('CREATE INDEX if not exists [dirs_idx1] ON dirs (filename,dirname);')
        cur.execute('CREATE INDEX if not exists [files_idx1] ON files (filename,filepath);')

        cur.executescript('drop view if exists dirs_unique; '
                          'create view dirs_unique as '
                          'select dirname, count(*) as pfcount from dirs group by dirname order by pfcount desc;')

        cur.executescript('drop view if exists ext_list_count; '
                          'create view ext_list_count as '
                          'select substr(filepath, -3, 3) as ext, count(*) as extcount from files '
                          'group by ext order by extcount desc;')

        cur.executescript('drop view if exists files_unique; '
                          'create view files_unique as '
                          'select filepath , count(*) as pfcount from files group by filepath order by pfcount desc;')

        cur.executescript('drop view if exists files_unique_archive; '
                          'create view files_unique_archive as '
                          'select * from files_unique where filepath like \'%.zip\' or filepath like \'%.rar\' or '
                          'filepath like \'%.7z\' or filepath like \'%gz\';')

        cur.executescript('drop view if exists files_unique_cpl; '
                          'create view files_unique_cpl as '
                          'select * from files_unique where filepath like \'%.cpl\';')

        cur.executescript('drop view if exists files_unique_dll; '
                          'create view files_unique_dll as '
                          'select * from files_unique where filepath like \'%.dll\';')

        cur.executescript('drop view if exists files_unique_docs; '
                          'create view files_unique_docs as '
                          'select * from files_unique where filepath like \'%.doc%\' or filepath like \'%.xls%\' or '
                          'filepath like \'%.ppt%\' or filepath like \'%.pdf\';')

        cur.executescript('drop view if exists files_unique_exe; '
                          'create view files_unique_exe as '
                          'select * from files_unique where filepath like \'%.exe\' or filepath like \'%.bat\' or filepath like \'%.com\';')

        cur.executescript('drop view if exists files_unique_images; '
                          'create view files_unique_images as '
                          'select * from files_unique where filepath like \'%.jpg\' or filepath like \'%.jpeg\' or '
                          'filepath like \'%.png\' or filepath like \'%.gif\';')

        cur.executescript('drop view if exists files_unique_python; '
                          'create view files_unique_python as '
                          'select * from files_unique where filepath like \'%.py\' or filepath like \'%.pyc\';')

        cur.executescript('drop view if exists files_unqiue_else; '
                          'create view files_unqiue_else as '
                          'select * from files_unique where '
                          'filepath not in (select filepath from files_unique_archive) and '
                          'filepath not in (select filepath from files_unique_cpl) and '
                          'filepath not in (select filepath from files_unique_dll) and '
                          'filepath not in (select filepath from files_unique_docs) and '
                          'filepath not in (select filepath from files_unique_exe) and '
                          'filepath not in (select filepath from files_unique_images) and '
                          'filepath not in (select filepath from files_unique_python);')

        cur.executescript('drop view if exists harddisk_list; '
                          'create view harddisk_list as '
                          'select path, count(*) as pathcount from '
                          '(select substr(dirname,0,25) as path from dirs union all '
                          'select substr(filepath,0,25) as path from files)'
                          'group by path;')

    except sqlite3.Error, error:
        print str(error)
        exit()


def sortTimestamps(directory):
    timestamps = []

    for i in os.listdir(directory):
        if i.endswith(".pf"):
            if os.path.getsize(directory + i) > 0:
                try:
                    p = Prefetch(directory + i)
                except Exception, e:
                    print "[ - ] {} could not be parsed".format(i)
                    continue
            else:
                continue
            
            start = 0
            end = 8
            while end <= len(p.lastRunTime):
                tstamp = struct.unpack_from("Q", p.lastRunTime[start:end])[0]

                if tstamp:
                    timestamps.append((tstamp, i[:-3]))
                    start += 8
                    end += 8
                else:
                    break
    
    return sorted(timestamps, key=lambda tup: tup[0], reverse=True)
    

def convertTimestamp(timestamp):
        # Timestamp is a Win32 FILETIME value
        # This function returns that value in a human-readable format
        return str(datetime(1601,1,1) + timedelta(microseconds=timestamp / 10.))



def main():
    p = ArgumentParser()
    p.add_argument("-c", "--csv", help="Present results in CSV format", action="store_true")
    p.add_argument("-d", "--directory", help="Parse all PF files in a given directory")
    p.add_argument("-e", "--executed", help="Sort PF files by ALL execution times")
    p.add_argument("-f", "--file", help="Parse a given Prefetch file")
    p.add_argument("-s", "--sqlite", help="Output data to SQLite database file")
    p.add_argument("-v", "--verbose", help="Output additional data to terminal", action="store_true")
    args = p.parse_args()

    if args.file:
        if args.file.endswith(".pf"):
            if os.path.getsize(args.file) > 0:
                try:
                    p = Prefetch(args.file)
                except Exception, e:
                    print "[ - ] {}".format(e)
                    sys.exit("[ - ] {} could not be parsed".format(args.file))
                
                if args.csv:
                    print "Last Executed, Executable Name, Run Count"
                    print "{}, {}-{}, {}".format(p.timestamps[0], p.executableName, p.hash, p.runCount)
                else:
                    p.prettyPrint(args.verbose)
            else:
                print "[ - ] {}: Zero byte Prefetch file".format(args.file)

    elif args.directory:
        if not (args.directory.endswith("/") or args.directory.endswith("\\")):
            sys.exit("\n[ - ] When enumerating a directory, add a trailing slash\n")

        if os.path.isdir(args.directory):
            if args.sqlite:
                global conn
                global cur
                conn = sqlite3.connect(args.sqlite)
                cur = conn.cursor()
                createSqlite()

            if args.csv:
                print "Last Executed, MFT Seq Number, MFT Record Number, Executable Name, Run Count"

                for i in os.listdir(args.directory):
                    if i.endswith(".pf"):
                        if os.path.getsize(args.directory + i) > 0:
                            try:
                                p = Prefetch(args.directory + i)
                            except Exception, e:
                                print "[ - ] {} could not be parsed".format(i)
                            print "{},{},{},{},{}".format(p.timestamps[0], p.mftSeqNumber, p.mftRecordNumber, p.executableName, p.runCount)
                        else:
                            print "[ - ] {}: Zero-byte Prefetch File".format(i)
                    else:
                        continue

            else:
                for i in os.listdir(args.directory):
                    if i.endswith(".pf"):
                        if os.path.getsize(args.directory + i):
                            try:
                                p = Prefetch(args.directory + i)
                                if args.sqlite:
                                    p.sqliteOutput()
                                else:
                                    p.prettyPrint(args.verbose)
                            except Exception, e:
                                print "[ - ] {} could not be parsed".format(i)
                        else:
                            print "[ - ] Zero-byte Prefetch file"

    elif args.executed:
        if not (args.executed.endswith("/") or args.executed.endswith("\\")):
            sys.exit("\n[ - ] When enumerating a directory, add a trailing slash\n")

        print "Execution Time, File Executed"
        for i in  sortTimestamps(args.executed):
            print "{}, {}".format(convertTimestamp(i[0]), i[1])


if __name__ == '__main__':
    main()
