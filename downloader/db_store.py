from dataclasses import dataclass, is_dataclass, fields, astuple
from datetime import datetime, timedelta
from enum import Enum
import psycopg
import logging

l = logging.getLogger(name=__name__)

INIT_TIME_STAMP = datetime(1970, 1, 1, 0, 0, 0)
INIT_INTERVAL = timedelta(seconds=0)


# unknown: initial status, waiting to be scheduled
# staged: already been scheduled in sandbox and under cnc probing
# dormant: CnC is found, but CnC communication is not observed
# active: CnC communication is observed
# interrupted: observing is interrupted, can be resumed
# unstaged: observing is stopped due to maximum dormant period reached
#           auto scheduling mode only
# error: some error status need to be further checked manually
# duplicate: bot with the same CnC already exist, no need to observe
class BotStatus(Enum):
    UNKNOWN = "unknown"
    STAGED = "staged"
    DORMANT = "dormant"
    ACTIVE = "active"
    INTERRUPTED = "interrupted"
    UNSTAGED = "unstaged"
    ERROR = "error"
    DUPLICATE = "duplicate"


class CnCStatus(Enum):
    UNKNOWN = "unknown"
    ALIVE = "alive"
    DISCONNECTED = "disconnected"


@dataclass
class TrackerInfo:
    id: str


@dataclass
class CnCInfo:
    ip: str
    port: int
    bot_id: str
    domain: str = ''
    asn: int = 0
    location: str = ''

    def __repr__(self):
        return f'{"ip":<8}: {self.ip}\n' + \
            f'{"port":<8}: {self.port}\n' + \
            f'{"bot_id":<8}: {self.bot_id}\n' + \
            f'{"domain":<8}: {self.domain}\n' + \
            f'{"asn":<8}: {self.asn}\n' + \
            f'{"location":<8}: {self.location}'


# dormant_at:
#   status -> active, reset to init value
#   status -> dormant, set the timestamp
# dormant_duration: always accrue, even after resuming from interrupted
# observe_at: set the timestamp when start observing after CnC is found
# observer_duration: always accrue, even after resuming from interrupted
@dataclass
class BotInfo:
    bot_id: str
    family: str
    first_seen: datetime
    last_seen: datetime = INIT_TIME_STAMP
    file_type: str = ''
    file_size: int = 0
    arch: str = ''
    endianness: str = ''
    bitness: int = 0
    status: str = 'unknown'
    dormant_at: datetime = INIT_TIME_STAMP
    dormant_duration: timedelta = INIT_INTERVAL
    observe_at: datetime = INIT_TIME_STAMP
    observe_duration: timedelta = INIT_INTERVAL
    tracker: str = ''

    @property
    def file_name(self):
        return self.bot_id + '.' + self.file_type

    @property
    def tag(self):
        return self.first_seen.strftime('%Y_%m_%d_%H_%M_%S') + '_' + self.family + '_' + self.bot_id[:8]

    @property
    def arch_spec(self):
        return self.arch + '_' + str(self.bitness) + '_' + self.endianness

    @property
    def upload_at(self):
        return self.first_seen.strftime("%Y-%m-%d %H:%M:%S")

    def __repr__(self):
        return f'{"bot_id":<16}: {self.bot_id}\n' + \
            f'{"family":<16}: {self.family}\n' + \
            f'{"first_seen":<16}: {self.first_seen.strftime("%Y-%m-%d %H:%M:%S")}\n' + \
            f'{"last_seen":<16}: {self.last_seen.strftime("%Y-%m-%d %H:%M:%S")}\n' + \
            f'{"file_type":<16}: {self.file_type}\n' + \
            f'{"file_size":<16}: {self.file_size}\n' + \
            f'{"arch":<16}: {self.arch}\n' + \
            f'{"endianness":<16}: {self.endianness}\n' + \
            f'{"bitness":<16}: {self.bitness}\n' + \
            f'{"status":<16}: {self.status}\n' + \
            f'{"dormant_at":<16}: {self.dormant_at.strftime("%Y-%m-%d %H:%M:%S")}\n' + \
            f'{"dormant_duration":<16}: {self.dormant_duration}\n' + \
            f'{"observe_at":<16}: {self.observe_at.strftime("%Y-%m-%d %H:%M:%S")}\n' + \
            f'{"observe_duration":<16}: {self.observe_duration}\n' + \
            f'{"tracker":<16}: {self.tracker}'


@dataclass
class CnCStat:
    ip: str
    port: int
    bot_id: str
    # could be: alive/disconnected
    status: str
    update_at: datetime

    def __repr__(self):
        return f'{"ip":<9}: {self.ip}\n' + \
            f'{"port":<9}: {self.port}\n' + \
            f'{"bot_id":<9}: {self.bot_id}\n' + \
            f'{"status":<9}: {self.status}\n' + \
            f'{"update_at":<9}: {self.update_at.strftime("%Y-%m-%d %H:%M:%S")}'


@dataclass
class AttackStat:
    bot_id: str
    cnc_ip: str
    # could be: connected/disconnected
    target: str
    attack_type: str
    time: datetime
    duration: timedelta


class DBStore:
    def __init__(self, host, port, dbname, user, psw):
        self.conn = None
        self.host = host
        self.port = port
        self.dbname = dbname
        self.user = user
        self.psw = psw

    async def open(self):
        conninfo = f'host={self.host} port={self.port} dbname={self.dbname} \
        user={self.user} password={self.psw}'
        self.conn = await psycopg.AsyncConnection.connect(conninfo)

    async def close(self):
        await self.conn.close()

    def _place_holder(self, field):
        #  _ph_ = {str: '%s', int: '%s'}
        #  return  _ph_[field.type]
        return "%s"

    async def _insert(self, tbl, data_obj):
        if is_dataclass(data_obj.__class__):
            if self.conn is not None:
                async with self.conn.cursor() as cur:
                    field_names = ','.join(f.name for f in fields(data_obj.__class__))
                    field_formats = ','.join(self._place_holder(f) for f in fields(data_obj.__class__))
                    field_values = astuple(data_obj)
                    sql = f"INSERT INTO {tbl} ({field_names}) VALUES ({field_formats})"
                    l.debug(f"sql: {sql}")
                    l.debug(f"para: {field_values}")
                    await cur.execute(sql, field_values)
                    await self.conn.commit()

    async def add_bot(self, bot):
        try:
            await self._insert('bot_info', bot)
        except psycopg.errors.UniqueViolation:
            l.error('add_bot failed due to UniqueViolation')

    async def add_tracker(self, tracker):
        await self._insert('tracker_info', tracker)

    async def load_bot_info(self, status_list=None, bot_id=None, count=None,
                            tracker=None):
        bots = []
        para = ()

        sql = "SELECT * FROM bot_info"
        filters = []
        if status_list is not None:
            if len(status_list) > 0:
                #  para += (tuple(status_list),)
                para += (status_list,)
                filters.append('status = ANY(%s)')
        if bot_id is not None:
            para += (bot_id,)
            filters.append('bot_id = %s')
        if tracker is not None:
            para += (tracker,)
            filters.append('tracker = %s')

        filter_str = ' AND '.join(f for f in filters)
        if len(filters) > 0:
            sql += ' WHERE '
            sql += filter_str
        sql += ' ORDER BY first_seen'

        if count is not None:
            para += (count,)
            sql += ' LIMIT %s'

        l.debug(f"sql: {sql}")
        l.debug(f"para: {para}")

        if self.conn is not None:
            async with self.conn.cursor() as cur:
                await cur.execute(sql, para)
                async for record in cur:
                    bots.append(BotInfo(*record))
        return bots

    async def update_bot_info(self, bot):
        if self.conn is not None:
            async with self.conn.cursor() as cur:
                field_updates = ','.join(f.name + '=' + self._place_holder(f) for f in fields(BotInfo))
                field_values = astuple(bot)
                sql = f"UPDATE bot_info SET {field_updates} WHERE bot_info.bot_id = %s"
                para = field_values + (bot.bot_id,)
                l.debug(f"sql: {sql}")
                l.debug(f"para: {para}")
                await cur.execute(sql, para)
                await self.conn.commit()

    async def bot_exists(self, bot_id):
        bots = await self.load_bot_info(None, bot_id)
        return len(bots) != 0

    async def add_cnc_info(self, cnc_info):
        await self._insert('cnc_info', cnc_info)

    async def load_cnc_info(self, bot_id=None, ip=None, port=None):
        cnc_info = []
        para = ()

        sql = "SELECT * FROM cnc_info"
        filters = []
        if bot_id is not None:
            para += (bot_id,)
            filters.append('bot_id = %s')
        if ip is not None:
            para += (ip,)
            filters.append('ip = %s')
        if port is not None:
            para += (port,)
            filters.append('port = %s')

        filter_str = ' AND '.join(f for f in filters)
        if len(filters) > 0:
            sql += ' WHERE '
            sql += filter_str

        l.debug(f"sql: {sql}")
        l.debug(f"para: {para}")

        if self.conn is not None:
            async with self.conn.cursor() as cur:
                await cur.execute(sql, para)
                async for record in cur:
                    cnc_info.append(CnCInfo(*record))
        return cnc_info

    async def cnc_exists(self, ip, port):
        cnc = await self.load_cnc_info(None, ip, port)
        return len(cnc) != 0

    async def add_cnc_stat(self, cnc_stat):
        await self._insert('cnc_stat', cnc_stat)

    async def load_cnc_stat(self, bot_id=None, ip=None):
        cnc_stat = []
        para = ()

        sql = "SELECT * FROM cnc_stat"
        filters = []
        if bot_id is not None:
            para += (bot_id,)
            filters.append('bot_id = %s')
        if ip is not None:
            para += (ip,)
            filters.append('ip = %s')

        filter_str = ' AND '.join(f for f in filters)
        if len(filters) > 0:
            sql += ' WHERE '
            sql += filter_str

        l.debug(f"sql: {sql}")
        l.debug(f"para: {para}")

        if self.conn is not None:
            async with self.conn.cursor() as cur:
                await cur.execute(sql, para)
                async for record in cur:
                    cnc_stat.append(CnCStat(*record))
        return cnc_stat

    async def add_attack_stat(self, attack):
        await self._insert('attack_stat', attack)


TEST_TS1 = datetime.strptime('2022-02-01 15:00:09', "%Y-%m-%d %H:%M:%S")
TEST_TS2 = datetime.strptime('2022-02-01 16:00:09', "%Y-%m-%d %H:%M:%S")
TEST_TS3 = datetime.strptime('2022-02-01 17:00:09', "%Y-%m-%d %H:%M:%S")
TEST_TS4 = datetime.strptime('2022-02-01 18:00:09', "%Y-%m-%d %H:%M:%S")


async def test_db_1(db_store):
    await db_store.open()
    b = BotInfo('00000000', 'mirai', TEST_TS1, INIT_TIME_STAMP, 'elf', 100)
    b1 = BotInfo('00000001', 'mirai', TEST_TS1, INIT_TIME_STAMP, 'elf', 100)
    print(f'add bot:\n{repr(b)}\n')
    await db_store.add_bot(b)
    print(f'add bot:\n{repr(b1)}\n')
    await db_store.add_bot(b1)
    bots = await db_store.load_bot_info()
    for bot in bots:
        print(f'{repr(bot)}\n')
    await db_store.close()


async def test_db_2(db_store):
    await db_store.open()
    check = await db_store.bot_exists('00000010')
    print(f'bot 00000001 exists? {check}')
    b = BotInfo('00000010', 'mirai', TEST_TS1, INIT_TIME_STAMP, 'elf', 100)
    b1 = BotInfo('00000011', 'mirai', TEST_TS1, INIT_TIME_STAMP, 'elf', 100)
    print(f'add bot:\n{repr(b)}\n')
    await db_store.add_bot(b)
    print(f'add bot:\n{repr(b1)}\n')
    await db_store.add_bot(b1)  # conflict
    check1 = await db_store.bot_exists('00000010')
    print(f'bot 00000001 exists? {check1}')
    await db_store.close()


async def test_db_3(db_store):
    await db_store.open()
    b = BotInfo('00000021', 'mirai', TEST_TS1, INIT_TIME_STAMP,
                'elf', 100, 'ARM', 'L', 32, 'unknown',
                TEST_TS2, INIT_INTERVAL, TEST_TS3, INIT_INTERVAL)
    b1 = BotInfo('00000022', 'mirai', TEST_TS1, INIT_TIME_STAMP,
                 'elf', 100, 'ARM', 'L', 32, 'active',
                 TEST_TS3, INIT_INTERVAL, TEST_TS4, INIT_INTERVAL)

    print(f'add bot:\n{repr(b)}\n')
    await db_store.add_bot(b)
    print(f'add bot:\n{repr(b1)}\n')
    await db_store.add_bot(b1)
    bots = await db_store.load_bot_info([], None, 2)
    for bot in bots:
        print(repr(bot))
    b1.status = 'dormant'
    print(f'update bot:\n{repr(b1)}\n')
    await db_store.update_bot_info(b1)
    bots = await db_store.load_bot_info(['unknown', 'active'], None, 2)
    for bot in bots:
        print(f'{repr(bot)}\n')
    bots = await db_store.load_bot_info(['unknown', 'dormant'], '12345678', 2)
    for bot in bots:
        print(f'{repr(bot)}\n')
    await db_store.close()


async def test_db_4(db_store):
    await db_store.open()
    check = await db_store.cnc_exists('109.123.1.1', 2323)
    print(f'cnc 109.123.1.1 exists? {check}')
    c = CnCInfo('109.123.1.1', 2323, '00000001', 'example.com', 0, 'China')
    print(f'add cncinfo:\n{repr(c)}\n')
    await db_store.add_cnc_info(c)
    check1 = await db_store.cnc_exists('109.123.1.1', 2323)
    print(f'cnc 109.123.1.1 exists? {check1}')
    c1 = CnCInfo('109.123.1.2', 2323, '00000011', 'sina.com', 0, 'China')
    print(f'add cncinfo:\n{repr(c1)}\n')
    await db_store.add_cnc_info(c1)
    cncs = await db_store.load_cnc_info()
    for cnc in cncs:
        print(f'{repr(cnc)}\n')
    cncs1 = await db_store.load_cnc_info('00000001')
    for cnc in cncs1:
        print(f'{repr(cnc)}\n')
    await db_store.close()


async def test_db_5(db_store):
    await db_store.open()
    c = CnCStat('109.123.1.1', 123, '00000051', 'alive', TEST_TS4)
    print(f'add cncstat:\n{repr(c)}\n')
    await db_store.add_cnc_stat(c)
    await db_store.close()


db_test_cases = {'case 1: BotInfo insert and load': test_db_1,
                 'case 2: BotInfo primary key conflict': test_db_2,
                 'case 3: BotInfo all fields insert, update and load with filter': test_db_3,
                 'case 4: CnCInfo insert and load': test_db_4,
                 'case 5: CnCStat insert and load': test_db_5}


# before doing the test, manually drop tables
async def test_db():
    print('start running db test cases...')
    db_store = DBStore('localhost', 5432, 'botnet_tracker', 'postgres', 'botnet')
    for k, v in db_test_cases.items():
        print(k)
        await v(db_store)
    print('done running db test cases')
