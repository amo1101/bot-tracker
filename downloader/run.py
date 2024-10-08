import os
import sys
import csv
import asyncio
from datetime import datetime
import logging
import shutil
import configparser
from bazaar import Bazaar
from elftools.elf.elffile import ELFFile
from db_store import *
from set_fw import *

CUR_DIR = os.path.dirname(os.path.abspath(__file__))

now = datetime.now()
current_time = now.strftime("%Y-%m-%d-%H-%M-%S")
logging.basicConfig(filename='bot-downloader-' + current_time + '.log',
                    filemode='w',
                    format='%(asctime)s-%(levelname)s-%(name)s: %(message)s', datefmt='%y-%m-%d %H:%M:%S',
                    level=logging.DEBUG)
#  logging.basicConfig(format='%(asctime)s-%(levelname)s-%(message)s', datefmt='%d-%b-%y %H:%M:%S', level=logging.DEBUG)
l = logging.getLogger(name=__name__)

valid_tags = None
max_batch = '100'
valid_file_type = ['elf']
valid_arch = {'MIPS': {32: ['B', 'L']}, 'ARM': {32: ['L']}, 'x86': {32: ['L']}, 'x64': {64: ['L']}}
download_period = 3600  # download hourly
g_bot_info_log = CUR_DIR + os.sep + 'bot_details.csv'

# record bot details
def log_bot_detail_info(botinfo, tags):
    bot_details = {
        'download_time': datetime.now(),
        'bot_id': botinfo.bot_id,
        'family': botinfo.family,
        'first_seen': botinfo.first_seen,
        'last_seen': botinfo.last_seen,
        'file_type': botinfo.file_type,
        'arch': botinfo.arch,
        'endianness': botinfo.endianness,
        'bitness': botinfo.bitness,
        'tags': ','.join(tags)
    }
    is_empty = os.stat(g_bot_info_log).st_size == 0 if \
        os.path.isfile(g_bot_info_log) else True
    with open(g_bot_info_log, 'a', newline='') as file:
        fieldnames = bot_details.keys()
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        if is_empty:
            writer.writeheader()
        writer.writerows([bot_details])

def get_arch_info(bot_file, bot_info):
    # unzipped file name should be sha256
    try:
        fi = open(bot_file, "rb")
        elffile = ELFFile(fi)
        bot_info.arch = elffile.get_machine_arch()
        if elffile.little_endian:
            bot_info.endianness = 'L'
        else:
            bot_info.endianness = 'B'
        bot_info.bitness = elffile.elfclass
        # filter out older version abi
        if bot_info.arch == 'ARM':
            if hex(elffile.header['e_flags']) != '0x4000002':
                bot_info.arch = 'ob-ARM'
    except Exception as e:
        l.error('An error occurred {e}')
        bot_info.arch = 'unknown'

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
    l.info('download base started...')
    #  enable_bazzar_access()
    for t in valid_tags:
        bot_list = remote_repo.bazaar_query('tag', t, max_batch)
        l.debug(f'response json: {bot_list}')
        if bot_list["query_status"] != "ok":
            continue
        for bot in bot_list["data"]:
            l.debug(f'bot: {bot}')
            exists = await db_store.bot_exists(bot['sha256_hash'])
            if exists:
                l.info(f'bot {bot["sha256_hash"]} already downloaded')
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
            if bot_info.first_seen < time_threshold:
                l.debug(f'{bot_info.bot_id} is too old.')
                continue
            if bot_info.file_type not in valid_file_type:
                l.debug(f'{bot_info.bot_id} file type not supported.')
                continue

            l.info(f'downloading {bot_info.bot_id}...')
            ret = remote_repo.bazaar_download(bot_info.bot_id)
            if ret == None:
                continue
            bot_file = bot_info.file_name
            get_arch_info(bot_file, bot_info)
            l.debug(f'bot_info:\n{repr(bot_info)}')
            log_bot_detail_info(bot_info, bot['tags'])

            if not check_arch_info(bot_info):
                l.info(f'{bot_info.bot_id} arch not supported.')
                os.remove(bot_file)
                continue
            shutil.move(bot_file, local_repo + os.sep + bot_file)
            l.debug('storing bot_info')
            await db_store.add_bot(bot_info)
            l.info(f'bot in stock {bot_info.bot_id}...')
    #  disable_bazzar_access()
    l.info('download base done')


async def download_recent(remote_repo, local_repo, db_store):
    l.info('download recent started...')
    #  enable_bazzar_access()
    bot_list = remote_repo.bazaar_list_samples('time')
    l.debug(f'response json: {bot_list}')
    if bot_list["query_status"] != "ok":
        l.debug('No result returned')
        return
    for bot in bot_list["data"]:
        exists = await db_store.bot_exists(bot['sha256_hash'])
        if exists:
            l.info(f'bot {bot["sha256_hash"]} already downloaded')
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
            l.info(f'{bot_info.bot_id} file type not supported.')
            continue
        find_tag = False
        for t in valid_tags:
            if t in bot["tags"]:
                find_tag = True
                bot_info.family = t
                break
        if not find_tag:
            continue
        l.info(f'downloading {bot_info.bot_id}...')
        remote_repo.bazaar_download(bot_info.bot_id)
        bot_file = bot_info.file_name
        get_arch_info(bot_file, bot_info)
        l.debug(f'bot_info:\n{repr(bot_info)}')
        log_bot_detail_info(bot_info, bot['tags'])

        if not check_arch_info(bot_info):
            l.info(f'{bot_info.bot_id} arch not supported.')
            os.remove(bot_file)
            continue
        l.debug('storing bot_info...')
        shutil.move(bot_file, local_repo + os.sep + bot_file)
        await db_store.add_bot(bot_info)
        l.info(f'bot in stock {bot_info.bot_id}...')
    #  disable_bazzar_access()
    l.info('download recent done')


async def tag_invalid_bots(db_store, local_repo):
    total = 0
    obsolete = 0
    l.info('Begin to tag invalid bots...')
    status = ['error', 'unstaged', 'unknown']
    bots = await db_store.load_bot_info(status)
    for b in bots:
        if b.arch == 'ARM':
            total += 1
            bf = local_repo + os.sep + b.bot_id + '.elf'
            get_arch_info(bf, b)
            if b.arch == 'ob-ARM':
                obsolete += 1
                l.debug(f'{b.bot_id} is obsolete!')
                #await db_store.update_bot_info(b)
    l.info(f'Finished tagging invalid bots, total: {total}, obsolete: {obsolete}')


async def async_main(tag_invalid=False):
    # await test_db()
    global valid_tags
    global max_batch
    config = configparser.ConfigParser()
    ini_file = CUR_DIR + os.sep + 'config.ini'
    if not os.path.exists(ini_file):
        l.error('ini file not exist!')
        return
    config.read(ini_file)

    valid_tags = config['downloader']['tags'].split(',')
    l.debug(f'valid tags: {valid_tags}')

    max_batch = config['downloader']['max_batch']
    l.debug(f'max_batch: {max_batch}')

    local_repo = config['downloader']['local_repo']
    base_time = config['downloader']['base_time']
    l.debug(f'local_repo: {local_repo}, base_time: {base_time}')
    if local_repo is None or not is_valid_datetime_format(base_time):
        l.error('Bad arguments')
        return

    time_threshold = datetime.strptime(base_time, '%Y-%m-%d %H:%M:%S')

    if not os.path.exists(local_repo):
        os.makedirs(local_repo)

    l.info('connecting to remote repo...')
    remote_repo = Bazaar(api_key=config['downloader']['api_key'])
    l.info('connecting to remote repo done')
    l.info('connecting to db...')
    db_store = DBStore(config['database']['host'],
                       config['database']['port'],
                       config['database']['dbname'],
                       config['database']['user'],
                       config['database']['password'])
    await db_store.open()
    l.info('connecting to db done')

    if tag_invalid:
        await tag_invalid_bots(db_store, local_repo)
        await db_store.close()
        return

    # get the base
    await download_base(remote_repo, local_repo, db_store, time_threshold)

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
    asyncio.run(async_main(), debug=True)
