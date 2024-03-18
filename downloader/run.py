import os
import sys
import datetime
import logging
from bazaar import Bazaar
from elftools.elf.elffile import ELFFile

now = datetime.now()
current_time = now.strftime("%m-%d-%Y-%H_%M_%S")
logging.basicConfig(filename='bot-downloader' + current_time + '.log', filemode='w', format='%(asctime)s-%(levelname)s-%(message)s',datefmt='%d-%b-%y %H:%M:%S')

def is_platform_supported(filename, supported_architectures):
    try:
        fi = open(filename,"rb")
        elffile = ELFFile(fi)
        arch = elffile.get_machine_arch()
        if arch in supported_architectures:
            if elffile.elfclass in supported_architectures[arch]:
                Endianness = ""
                if elffile.little_endian:
                    Endianness = "L"
                else:
                    Endianness = "B"
                if Endianness in supported_architectures[arch][elffile.elfclass]:
                    return True
                else:
                    l.warning("File %s Endianness %s is not supported", filename, Endianness)
                    return False
            else:
                l.warning("File %s address size %d is not supported", filename, elffile.elfclass)
                return False
        else:
            l.warning("File %s architecture %s is not supported", filename, arch)
            return False
    except:
        l.error("Coudln't parse file %s (supposed to be elf)",filename)
        return False

def main():
    repo = Bazaar()

    # get the base
    base_list = repo.bazaar_query()
