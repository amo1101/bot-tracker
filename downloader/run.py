import os
import sys
import asyncio
import datetime
import logging
import shutil
import argparse
from bazaar import Bazaar
from elftools.elf.elffile import ELFFile
from datetime import datetime

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
DB_MODULE_DIR = os.path.dirname(CUR_DIR) + os.sep + 'db'
sys.path.append(DB_MODULE_DIR)

from db_store import BotStatus, BotInfo, TrackerInfo, DBStore

#  now = datetime.now()
#  current_time = now.strftime("%m-%d-%Y-%H_%M_%S")
#  logging.basicConfig(filename='bot-downloader' + current_time + '.log', filemode='w', format='%(asctime)s-%(levelname)s-%(message)s',datefmt='%d-%b-%y %H:%M:%S')

valid_tags = ['mirai']
valid_file_type = ['elf']
valid_arch = {'MIPS': {32: ['B','L']}, 'ARM': {32: ['L']}}
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
    if bot_info.arch in valid_arch and \
       bot_info.bitness in valid_arch[bot_info.arch] and \
       bot_info.endianness in valid_arch[bot_info.arch][bot_info.bitness]:
        return True
    return False

def is_earlier(t1_str, t2_str):
    dt1 = datetime.strptime(t1_str, '%Y-%m-%d %H:%M:%S')
    dt2 = datetime.strptime(t2_str, '%Y-%m-%d %H:%M:%S')
    return dt1 < dt2

async def download_base(remote_repo, local_repo, db_store, time_threshold):
    for t in valid_tags:
        bot_list = remote_repo.bazaar_query('tag', t, '1000')
        for bot in bot_list["data"]:
            bot_info = BotInfo(bot["sha256_hash"], t, bot["first_seen"],
                               bot["last_seen"], bot["file_type"],
                               bot["file_size"])
            if is_earlier(bot_info.first_seen, time_threshold) or bot_info.file_type \
                not in valid_file_type:
                continue
            remote_repo.bazaar_download(bot_info.bot_id)
            bot_file = bot_info.bot_id
            get_arch_info(bot_file, bot_info)
            if not check_arch_info(bot_info):
                os.remove(bot_file)
                continue
            shutil.move(bot_file, local_repo + os.sep + bot_file)
            await db_store.add_bot(bot_info)

async def download_recent(remote_repo, local_repo, db_store):
    bot_list = remote_repo.bazaar_list_samples('time')
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
        if not find_tag:
            continue
        remote_repo.bazaar_download(bot_info.bot_id)
        bot_file = bot_info.bot_id
        get_arch_info(bot_file, bot_info)
        if not check_arch_info(bot_info):
            os.remove(bot_file)
            continue
        shutil.move(bot_file, local_repo + os.sep + bot_file)
        await db_store.add_bot(bot_info)

async def async_main(local_repo, base_time):
    remote_repo = Bazaar()
    db_store = DBStore()
    await db_store.open()

    # get the base
    await download_base(remote_repo, local_repo, db_store, base_time)

    # get bots incrementally
    try:
        while True:
            await asyncio.sleep(download_period)
            await download_recent(remote_repo, local_repo, db_store)
    except KeyboardInterrupt:
        print('Interrupted by user')
    finally:
        await db_store.close()

def is_valid_datetime_format(datetime_str):
    try:
        datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
        return True
    except ValueError:
        return False

if __name__ == "__main__":
    #  print(BANNER)
    #  signal.signal(signal.SIGINT, recv_signal)
    #  print("[Master] Press CTRL+C whenever you want to exit")
    parser = argparse.ArgumentParser()
    parser.add_argument("-local_repo", nargs='*', type=str, help="The path to store malware samples")
    parser.add_argument("-base_time", nargs='*', type=str, help="The base time \
    after which the malware will be downloaded, e.g.2024-03-22 23:59:59")
    args = parser.parse_args()
    print(f'local_repo: {args.local_repo}')
    print(f'base_time: {args.base_time}')
    if args.local_repo is None or args.base_time is None:
        print('Bad arguments')
        sys.exit()

    if args.local_repo[0] is None or not is_valid_datetime_format(args.base_time[0]):
        print('Bad arguments')
        sys.exit()

    if not os.path.exists(args.local_repo[0]):
        os.makedirs(args.local_repo[0])

    asyncio.run(async_main(args.local_repo[0], args.base_time[0]), debug=True)

