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
from db_store import *

CUR_DIR = os.path.dirname(os.path.abspath(__file__))

#  now = datetime.now()
#  current_time = now.strftime("%m-%d-%Y-%H_%M_%S")
#  logging.basicConfig(filename='bot-downloader' + current_time + '.log', filemode='w', format='%(asctime)s-%(levelname)s-%(message)s',datefmt='%d-%b-%y %H:%M:%S')
logging.basicConfig(format='%(asctime)s-%(levelname)s-%(message)s', datefmt='%d-%b-%y %H:%M:%S', level=logging.DEBUG)
l = logging.getLogger(name=__name__)

valid_tags = ['mirai']
valid_file_type = ['elf']
valid_arch = {'MIPS': {32: ['B', 'L']}, 'ARM': {32: ['L']}}
download_period = 10  # download hourly

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


def is_valid_datetime_format(t_str):
    try:
        if t_str == '' or t_str is None:
            return True
        datetime.strptime(t_str, '%Y-%m-%d %H:%M:%S')
        return True
    except ValueError:
        return False


def get_timestamp(timestr):
    if timestr == '' or timestr is None:
        return INIT_TIME_STAMP
    else:
        return datetime.strptime(timestr, '%Y-%m-%d %H:%M:%S')


async def download_base(remote_repo, local_repo, db_store, time_threshold):
    l.debug('download base started...')
    for t in valid_tags:
        bot_list = remote_repo.bazaar_query('tag', t, '2')
        l.debug(f'response json: {bot_list}')
        if bot_list["query_status"] != "ok":
            continue
        for bot in bot_list["data"]:
            l.debug(f'bot: {bot}')
            exists = await db_store.bot_exists(bot['sha256_hash'])
            if exists:
                l.debug(f'bot {bot["sha256_hash"]} already downloaded')
                continue
            if not is_valid_datetime_format(bot['first_seen']) or \
                    not is_valid_datetime_format(bot['last_seen']):
                l.warning('wrong timestamp format.')
                continue
            bot_info = BotInfo(bot["sha256_hash"], t,
                               get_timestamp(bot["first_seen"]),
                               get_timestamp(bot["last_seen"]),
                               bot["file_type"],
                               bot["file_size"])
            if bot_info.first_seen < time_threshold or bot_info.file_type \
                    not in valid_file_type:
                continue
            l.debug(f'downloading {bot_info.bot_id}...')
            remote_repo.bazaar_download(bot_info.bot_id)
            bot_file = bot_info.file_name
            get_arch_info(bot_file, bot_info)
            l.debug(f'bot_info:\n{repr(bot_info)}')
            if not check_arch_info(bot_info):
                os.remove(bot_file)
                continue
            shutil.move(bot_file, local_repo + os.sep + bot_file)
            l.debug('storing bot_info')
            await db_store.add_bot(bot_info)
    l.debug('download base done')


async def download_recent(remote_repo, local_repo, db_store):
    l.debug('download recent started...')
    bot_list = remote_repo.bazaar_list_samples('time')
    l.debug(f'response json: {bot_list}')
    if bot_list["query_status"] != "ok":
        l.debug('No result returned')
        return
    for bot in bot_list["data"]:
        exists = await db_store.bot_exists(bot['sha256_hash'])
        if exists:
            l.debug(f'bot {bot["sha256_hash"]} already downloaded')
            continue
        if not is_valid_datetime_format(bot['first_seen']) or \
                not is_valid_datetime_format(bot['last_seen']):
            l.warning('wrong timestamp format.')
            continue
        bot_info = BotInfo(bot["sha256_hash"], '',
                           get_timestamp(bot["first_seen"]),
                           get_timestamp(bot["last_seen"]),
                           bot["file_type"],
                           bot["file_size"])

        if bot_info.file_type not in valid_file_type:
            continue
        find_tag = False
        for t in valid_tags:
            if t in bot["tags"]:
                find_tag = True
                bot_info.family = t
                break
        if not find_tag:
            continue
        l.debug(f'downloading {bot_info.bot_id}...')
        remote_repo.bazaar_download(bot_info.bot_id)
        bot_file = bot_info.file_name
        get_arch_info(bot_file, bot_info)
        l.debug(f'bot_info:\n{repr(bot_info)}')
        if not check_arch_info(bot_info):
            os.remove(bot_file)
            continue
        l.debug('storing bot_info...')
        shutil.move(bot_file, local_repo + os.sep + bot_file)
        await db_store.add_bot(bot_info)
    l.debug('download recent done')


async def async_main(local_repo, base_time):
    #await test_db()
    #return
    l.debug('connecting to remote repo...')
    remote_repo = Bazaar()
    l.debug('connecting to remote repo done')
    l.debug('connecting to db...')
    db_store = DBStore()
    await db_store.open()
    l.debug('connecting to db done')

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

    time_threshold = datetime.strptime(args.base_time[0], '%Y-%m-%d %H:%M:%S')

    if not os.path.exists(args.local_repo[0]):
        os.makedirs(args.local_repo[0])

    asyncio.run(async_main(args.local_repo[0], time_threshold), debug=True)
