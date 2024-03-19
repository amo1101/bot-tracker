import os
import sys
import datetime
import logging
import shutil
from bazaar import Bazaar
from elftools.elf.elffile import ELFFile
from db import BotInfo, TrackerInfo, DBStore

now = datetime.now()
current_time = now.strftime("%m-%d-%Y-%H_%M_%S")
logging.basicConfig(filename='bot-downloader' + current_time + '.log', filemode='w', format='%(asctime)s-%(levelname)s-%(message)s',datefmt='%d-%b-%y %H:%M:%S')

valid_tags = ['mirai']
valid_file_type = ['elf']
valid_arch = {'mips': ['32'], 'mipsel': ['32'], 'armv7l':['32']}
local_repo = './'
download_period = 3600 # download hourly

def get_arch_info(bot_file, bot_info):
    # unzipped file name should be sha256
    fi = open(bot_file, "rb")
    elffile = ELFFile(fi)
    bot_info.arch = elffile.get_machine_arch()
    if elffile.little_endian:
        bot_info.endianness = 'L'
    else:
        bot_info.endianness = 'B'
    bot_info.bitness = elffile.elfclass

def check_arch_info(bot_info):
    pass

def download_base(db_store, time_threshold):
    repo = Bazaar()
    for t in valid_tags:
        bot_list = repo.bazaar_query('tag', t, '1000')
        for bot in bot_list["data"]:
            bot_info = BotInfo(bot["sha256_hash"], t, bot["first_seen"],
                               bot["last_seen"], bot["file_type"],
                               bot["file_size"])
            if bot_info.first_seen < time_threshold or bot_info.file_type \
                not in valid_file_type:
                continue
            repo.bazaar_download(bot_info.sha256)
            bot_file = bot_info.sha256
            get_arch_info(bot_file, bot_info)
            if not check_arch_info(bot_info):
                os.remove(bot_file)
                continue
            shutil.move(bot_file, local_repo + os.sep + bot_file)
            db_store.add_bot(bot_info)
    db_store.persist()

def download_recent(db_store):
    repo = Bazaar()
    bot_list = repo.bazaar_list_samples('time')
    for bot in bot_list["data"]:
        bot_info = BotInfo(bot["sha256_hash"], t, bot["first_seen"],
                           bot["last_seen"], bot["file_type"],
                           bot["file_size"])
        if bot_info.file_type not in file_type:
                continue
        find_tag = False
        for t in valid_tags:
            if t in bot["tags"]:
                find_tag = True
                break
        repo.bazaar_download(bot_info.sha256)
        bot_file = bot_info.sha256
        get_arch_info(bot_file, bot_info)
        if not check_arch_info(bot_info):
            os.remove(bot_file)
            continue
        shutil.move(bot_file, local_repo + os.sep + bot_file)
        db_store.add_bot(bot_info)
    db_store.persist()


def main():
    repo = Bazaar()
    bot_info_store = BotInfoStore()

    # get the base
    time_threshold = None
    download_base(bot_info_store, time_threshold)

    # get bots incrementally
    while True:
        time.sleep(download_period)
        download_recent(bot_info_store)

