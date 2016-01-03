#! Python3
# fileHasher.py - Hashes files, time stamps, and logs them
# author - Dahtse
# January 2016
# v 0.4   started with quick fish recently posted to site, added questions for user - command line is ugly

import argparse
import csv
import hashlib
import logging
import openpyxl
import os
import stat
import sys
import time


def ParseCommandLine():
    parser = argparse.ArgumentParser('File system hasher .. Filehasher')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-v', "--verbose", help="Displays progress messages", action='store_true')
    group.add_argument('-s', "--spinner", help="displays progress indicator", action='store_true')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--md5', help='specifies MD5 algorithm', action='store_true')
    group.add_argument('--sha1', help='specifies SHA1 algorithm', action='store_true')
    group.add_argument('--sha224', help='specifies SHA224 algorithm', action='store_true')
    group.add_argument('--sha256', help='specifies SHA256 algorithm', action='store_true')
    group.add_argument('--sha384', help='specifies SHA384 algorithm', action='store_true')
    group.add_argument('--sha512', help='specifies SHA512 algorithm', action='store_true')

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--md5a', help='specifies MD5 algorithm', action='store_true')
    group.add_argument('--sha1a', help='specifies SHA1 algorithm', action='store_true')
    group.add_argument('--sha224a', help='specifies SHA224 algorithm', action='store_true')
    group.add_argument('--sha256a', help='specifies SHA256 algorithm', action='store_true')
    group.add_argument('--sha384a', help='specifies SHA384 algorithm', action='store_true')
    group.add_argument('--sha512a', help='specifies SHA512 algorithm', action='store_true')

    parser.add_argument('-d', '--rootPath', type=ValidateDirectory, required=True,
                        help="specify the root path for hashing")
    parser.add_argument('-r', '--reportPath', type=ValidateDirectoryWritable, required=True,
                        help="specify the path for reports and logs will be written")
    parser.add_argument('-m', '--hashMatch', type=ValidateFileReadable, required=False,
                        help="specify the optional hashmatch input file path")

    global gl_args
    global gl_hashType
    global gl_hashTypeAlt
    global gl_hashMatch
    global gl_hashDict
    global gl_verbose
    global gl_spinner

    gl_args = parser.parse_args()

    if gl_args.verbose:
        gl_verbose = True
    else:
        gl_verbose = False

    if gl_args.spinner:
        gl_spinner = True
    else:
        gl_spinner = False

    # Determine the hash type(s) selected


    if gl_args.md5:
        gl_hashType = 'MD5'

    elif gl_args.sha1:
        gl_hashType = 'SHA1'

    elif gl_args.sha224:
        gl_hashType = 'SHA224'

    elif gl_args.sha256:
        gl_hashType = 'SHA256'

    elif gl_args.sha384:
        gl_hashType = 'SHA384'

    elif gl_args.sha512:
        gl_hashType = 'SHA512'

    else:
        gl_hashType = "Unknown"
        logging.error('Unknown Hash Type Specified')

    # Optional Type

    if gl_args.md5a:
        gl_hashTypeAlt = 'MD5'

    elif gl_args.sha1a:
        gl_hashTypeAlt = 'SHA1'

    elif gl_args.sha224a:
        gl_hashTypeAlt = 'SHA224'

    elif gl_args.sha256a:
        gl_hashTypeAlt = 'SHA256'

    elif gl_args.sha384a:
        gl_hashTypeAlt = 'SHA384'

    elif gl_args.sha512a:
        gl_hashTypeAlt = 'SHA512'
    else:
        gl_hashTypeAlt = 'None'

    # Check for hashMatch Selection
    if gl_args.hashMatch:
        # Create a dictionary from the input file
        gl_hashMatch = gl_args.hashMatch
        gl_hashDict = {}

        try:
            with open(gl_hashMatch) as fp:
                # for each line in the file extract the hash and id
                # then store the result in a dictionary
                # key, value pair
                # in this case the hash is the key and id is the value

                for line in fp:
                    hashKey = line.split(',')[0].upper()
                    hashID = line.split(',')[1]
                    # Strip the newline from the ID
                    hashID = hashID.strip()
                    # Add the key value pair to the dictionary
                    gl_hashDict[hashKey] = hashID

        except:
            logging.error("Failed to read in Hash List")
            DisplayMessage("Failed to read in Hash List")
    else:
        gl_hashMatch = False

    DisplayMessage("Command line processed: Successfully")

    return

def ValidateDirectory(theDir):
    if not os.path.isdir(theDir):
        raise argparse.ArgumentTypeError('Directory does not exist')

    if os.access(theDir, os.R_OK):
        return theDir
    else:
        raise argparse.ArgumentTypeError('Directory is not readable')

def ValidateDirectoryWritable(theDir):
    if not os.path.isdir(theDir):
        raise argparse.ArgumentTypeError('Directory does not exist')

    if os.access(theDir, os.W_OK):
        return theDir
    else:
        raise argparse.ArgumentTypeError('Directory is not writable')

def ValidateFileReadable(theFile):
    if not os.path.isfile(theFile):
        raise argparse.ArgumentTypeError('File does not exist')

    if os.access(theFile, os.R_OK):
        return theFile
    else:
        raise argparse.ArgumentTypeError('File is not readable')


class Spinner:
    # Constructor

    def __init__(self):
        self.symbols = [' |', ' /', ' -', ' \\', ' |', ' \\', ' -', 'END']
        self.curSymbol = 0

        sys.stdout.write("\b\b\b%s " % self.symbols[self.curSymbol])
        sys.stdout.flush()

    def Spin(self):
        if self.symbols[self.curSymbol] == 'END':
            self.curSymbol = 0

        sys.stdout.write("\b\b\b%s " % self.symbols[self.curSymbol])
        sys.stdout.flush()
        self.curSymbol += 1


def WalkPath():
    processCount = 0
    errorCount = 0

    # Create a proper report path
    reportPath = os.path.join(gl_args.reportPath, "filehash.csv")
    oCVS = _CSVWriter(reportPath, gl_hashType, gl_hashTypeAlt)

    if gl_args.rootPath.endswith('\\') or gl_args.rootPath.endswith('/'):
        rootPath = gl_args.rootPath
    else:
        rootPath = gl_args.rootPath + '/'

    logging.info('Start Scan Path: ' + rootPath)

    if gl_args.spinner:
        # Create a Spinner Object for displaying progress
        obSPIN = Spinner()

    for root, dirs, files in os.walk(rootPath):

        if gl_spinner:
            # Update progress indicator
            obSPIN.Spin()

        # for each file obtain the filename and call the HashFile Function
        for file in files:
            fname = os.path.join(root, file)
            result = HashFile(fname, file, oCVS)

            # if hashing was successful then increment the ProcessCount
            if result is True:
                processCount += 1
            # if not sucessful, the increment the ErrorCount
            else:
                errorCount += 1

    oCVS.writerClose()

    return (processCount)


# End WalkPath==================================================


#
# Name: HashFile Function
#
# Desc: Processes a single file which includes performing a hash of the file
#           and the extraction of metadata regarding the file processed
#           use Python Standard Library modules hashlib, os, and sys
#
# Input: theFile = the full path of the file
#           simpleName = just the filename itself
#  
# Actions: 
#              Attempts to hash the file and extract metadata
#              Call GenerateReport for successful hashed files
#
def HashFile(theFile, simpleName, o_result):
    if os.path.exists(theFile):

        # Verify that the path is not a symbolic link
        if not os.path.islink(theFile):

            # Verify that the file is real
            if os.path.isfile(theFile):

                try:
                    # Attempt to open the file
                    f = open(theFile, 'rb')
                except IOError:
                    # if open fails report the error
                    logging.warning('Open Failed: ' + theFile)
                    return
                else:
                    try:
                        # Get the Basic File Attributes
                        # Before attempting to open the file
                        # This should preserve the access time on most OS's

                        theFileStats = os.stat(theFile)
                        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(theFile)

                        # Attempt to read the file
                        rd = f.read()

                    except IOError:
                        # if read fails, then close the file and report error
                        f.close()
                        logging.warning('File Access Error: ' + theFile)
                        return
                    else:

                        # Print the simple file name
                        DisplayMessage("Processing File: " + theFile)
                        logging.info("Processing File: " + theFile)

                        # Get the size of the file in Bytes
                        fileSize = str(size)

                        # Get MAC Times
                        modifiedTime = time.ctime(mtime)
                        accessTime = time.ctime(atime)
                        createdTime = time.ctime(ctime)

                        ownerID = str(uid)
                        groupID = str(gid)
                        fileMode = bin(mode)

                        # process the file hashes

                        if gl_args.md5:
                            # Calculate and Print the MD5
                            hash = hashlib.md5()
                            hash.update(rd)
                            hexMD5 = hash.hexdigest()
                            hashValue = hexMD5.upper()
                        elif gl_args.sha1:
                            hash = hashlib.sha1()
                            hash.update(rd)
                            hexSHA1 = hash.hexdigest()
                            hashValue = hexSHA1.upper()
                        elif gl_args.sha224:
                            hash = hashlib.sha224()
                            hash.update(rd)
                            hexSHA224 = hash.hexdigest()
                            hashValue = hexSHA224.upper()
                        elif gl_args.sha256:
                            hash = hashlib.sha256()
                            hash.update(rd)
                            hexSHA256 = hash.hexdigest()
                            hashValue = hexSHA256.upper()
                        elif gl_args.sha384:
                            hash = hashlib.sha384()
                            hash.update(rd)
                            hexSHA384 = hash.hexdigest()
                            hashValue = hexSHA384.upper()
                        elif gl_args.sha512:
                            # Calculate and Print the SHA512
                            hash = hashlib.sha512()
                            hash.update(rd)
                            hexSHA512 = hash.hexdigest()
                            hashValue = hexSHA512.upper()
                        else:
                            logging.error('Hash not Selected')

                        if gl_args.md5a:
                            # Calculate and Print the MD5 alternate
                            hash = hashlib.md5()
                            hash.update(rd)
                            hexMD5 = hash.hexdigest()
                            hashValueAlt = hexMD5.upper()
                        elif gl_args.sha1a:
                            hash = hashlib.sha1()
                            hash.update(rd)
                            hexSHA1 = hash.hexdigest()
                            hashValueAlt = hexSHA1.upper()
                        elif gl_args.sha224a:
                            hash = hashlib.sha224()
                            hash.update(rd)
                            hexSHA224 = hash.hexdigest()
                            hashValueAlt = hexSHA224.upper()
                        elif gl_args.sha256a:
                            hash = hashlib.sha256()
                            hash.update(rd)
                            hexSHA256 = hash.hexdigest()
                            hashValueAlt = hexSHA256.upper()
                        elif gl_args.sha384a:
                            hash = hashlib.sha384()
                            hash.update(rd)
                            hexSHA384 = hash.hexdigest()
                            hashValueAlt = hexSHA384.upper()
                        elif gl_args.sha512a:
                            hash = hashlib.sha512()
                            hash.update(rd)
                            hexSHA512 = hash.hexdigest()
                            hashValueAlt = hexSHA512.upper()
                        else:
                            hashValueAlt = "Not Selected"

                        # Check if hash matching was selected
                        if gl_hashMatch:
                            # If yes then check to see if we have a match
                            # and if we do save the result
                            if hashValue in gl_hashDict:
                                DisplayMessage("Hash Match")
                                foundValue = "Found"
                                foundID = gl_hashDict[hashValue]
                            elif hashValueAlt in gl_hashDict:
                                DisplayMessage("Hash Match")
                                foundValue = "Found"
                                foundID = gl_hashDict[hashValueAlt]
                            else:
                                foundValue = ""
                                foundID = ""
                        else:
                            # Matching not set
                            foundValue = ""
                            foundID = ""

                        # write one row to the output file

                        resultList = [simpleName, foundValue, foundID, theFile, fileSize, modifiedTime, accessTime,
                                      createdTime, hashValue, hashValueAlt, ownerID, groupID, str(mode)]
                        o_result.writeCSVRow(resultList)

                        DisplayMessage("================================")
                        return True
            else:
                logging.warning('[' + repr(simpleName) + ', Skipped NOT a File' + ']')
                return False
        else:
            logging.warning('[' + repr(simpleName) + ', Skipped Link NOT a File' + ']')
            return False
    else:
        logging.warning('[' + repr(simpleName) + ', Path does NOT exist' + ']')
    return False


def DisplayMessage(msg):
    if gl_verbose:
        print(msg)

    return


class _CSVWriter:
    def __init__(self, fileName, hashType, hashTypeAlt):
        try:
            # create a writer object and then write the header row
            if (sys.version_info > (3, 0)):
                self.csvFile = open(fileName, 'w', newline="\r\n")
            else:
                self.csvFile = open(fileName, 'w')

            tempList = ['File', 'Match', 'ID', 'Path', 'Size', 'Modified Time', 'Access Time', 'Created Time', hashType,
                        hashTypeAlt, 'Owner', 'Group', 'Mode']
            outStr = ",".join(tempList)
            self.csvFile.write(outStr)
            self.csvFile.write("\n")
        except:
            logging.error('CSV File Open Failure')
            DisplayMessage("Error Opening CSV File")
            DisplayMessage("Make sure CSV File Location is Writable and Ensure the file is not open")
            quit()

    def writeCSVRow(self, outList):
        outStr = ",".join(outList)
        self.csvFile.write(outStr)
        self.csvFile.write("\n")

    def writerClose(self):
        self.csvFile.close()


if __name__ == '__main__':
    FILEHASHER_VERSION = '0.4'
    ReleaseDate = "January 3, 2016"
    logging.basicConfig(filename='FILEHASHER.log', level=logging.DEBUG, format='%(asctime)s %(message)s')
    organization_name = input("Provide your organization name:  ")
    investigation_name = input("Provide your investigation name:  ")
    case_number = input("Provide your case number or type 'none': ")
    comments = input("Please provide additional comments:  ")
    print("System time, date, and time zone is currently set as " + time.strftime('%X %x %Z'))

    ParseCommandLine()

    startTime = time.time()

    # Record the Welcome Message
    logging.info('')
    logging.info(organization_name + ': ' + investigation_name + ': case: ' + case_number)
    logging.info(comments)
    logging.info('Version' + FILEHASHER_VERSION)
    logging.info('Release Date: ' + ReleaseDate)
    logging.info('\nStart Scan\n')
    logging.info('')
    DisplayMessage('Wecome to FileHasher Version: ' + FILEHASHER_VERSION + ' Release Date: ' + ReleaseDate + '\n')

    # Record some information regarding the system
    logging.info('System:  ' + sys.platform)
    logging.info('Version: ' + sys.version)

    # Traverse the file system directories and hash the files
    filesProcessed = WalkPath()

    # Record the end time and calculate the duration
    endTime = time.time()
    duration = endTime - startTime

    logging.info('Files Processed: ' + str(filesProcessed))
    logging.info('Elapsed Time: ' + str(duration) + ' seconds')
    logging.info('')
    logging.info('Program Terminated Normally')
    logging.info('')

    DisplayMessage('Files Processed: ' + str(filesProcessed))
    DisplayMessage('Elapsed Time: ' + str(duration) + ' seconds')
    DisplayMessage('')
    DisplayMessage("Program End")
