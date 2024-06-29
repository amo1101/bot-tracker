import os
import sys
import elftools
from elftools.elf.elffile import ELFFile
from pathlib import Path

MAL_REPO='/home/frank/code/bot-tracker/downloader/malware_repo'
def get_arch_info(bot_file):
    # unzipped file name should be sha256
    arch = ''
    endianness = ''
    bitness = 0
    eabi = ''
    try:
        with open(bot_file, "rb") as fi:
            elffile = ELFFile(fi)
            arch = elffile.get_machine_arch()
            if elffile.little_endian:
                endianness = 'L'
            else:
                endianness = 'B'
            bitness = elffile.elfclass
            if arch == 'ARM':
                eabi = hex(elffile.header['e_flags'])
    except elftools.common.exceptions.ELFError:
        return '','',0,0
    finally:
        pass
    return arch, endianness, bitness, eabi


def list_all_files(directory):
    path = Path(directory)
    return [str(file) for file in path.rglob('*') if file.is_file()]

if __name__ == "__main__":
    bots = list_all_files(MAL_REPO)
    o = 0
    t = 0
    for b in bots:
        a,e,l,i = get_arch_info(b)
        if a == 'ARM':
            t += 1
            if i != '0x4000002':
                print(f'{b}:{a},{e},{l},{i}')
                #os.remove(b)
                o += 1
    print(f'total: {t}, removed: {o}')
