import os
import sys
import psycopg
from enum import Enum
from dataclasses import dataclass, is_dataclass, fields, astuple

class BotStatus(Enum):
    UNKNOWN = "unknown"
    STARTED = "started"
    DORMANT = "dormant"
    ACTIVE = "active"
    PAUSED = "paused"
    INTERRUPTED = "interrupted"
    STOPPED = "stopped"
    ERROR = "error"

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
    port: str
    bot_id: str
    asn: int
    location: str

@dataclass
class BotInfo:
    bot_id: str
    family: str
    first_seen: str
    last_seen: str = '1970-01-01 00:00:00'
    file_type: str = ''
    file_size: int = 0
    arch: str = ''
    endianness: str = ''
    bitness: int = 0
    status: str = 'unknown'
    dormant_at: str = '1970-01-01 00:00:00'
    dormant_duration: str = 'P0Y0M0DT0H0M0S'
    observe_at: str = '1970-01-01 00:00:00'
    observe_duration: str = 'P0Y0M0DT0H0M0S'
    tracker: str = ''

@dataclass
class CnCStat:
    ip: str
    # could be: connected/disconnected
    status: str
    time: str

# TODO
@dataclass
class AttackStat:
    bot_id: str
    cnc_ip: str
    # could be: connected/disconnected
    target: str
    attack_type: str
    time: str
    duration: str

class DBStore:
    def __init__(self):
        self.conn = None

    async def open(self):
        conninfo = 'host=localhost port=5432 dbname=botnet_tracker \
        user=postgres password=botnet'
        self.conn = await psycopg.AsyncConnection.connect(conninfo)

    async def close(self):
        await self.conn.close()

    def _place_holder(self, field):
        _ph_ = {str: '%s', int: '%s'}
        return  _ph_[field.type]

    async def _insert(self, tbl, data_obj):
        if is_dataclass(data_obj.__class__):
            if self.conn is not None:
                async with self.conn.cursor() as cur:
                    field_names = ','.join(f.name for f in fields(data_obj.__class__))
                    field_formats = ','.join(self._place_holder(f) for f in fields(data_obj.__class__))
                    field_values = astuple(data_obj)
                    sql = f"INSERT INTO {tbl} ({field_names}) VALUES ({field_formats})"
                    print(f"sql: {sql}")
                    await cur.execute(sql, field_values)
                    await self.conn.commit()

    async def add_bot(self, bot):
        try:
            await self._insert('bot_info', bot)
        except psycopg.errors.UniqueViolation:
            pass #TODO: should return false

    async def add_tracker(self, tracker):
        await self._insert('tracker_info', tracker)

    #TODO
    async def load_bot_info(self, status_list=None, bot_id=None, count=None,
                            tracker=None):
        bots = []
        status_tuple = ()
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

        print(f"sql: {sql}")
        print(f"para: {para}")

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
                print(f"sql: {sql}")
                await cur.execute(sql, field_values + (bot.bot_id,))
                await self.conn.commit()

    async def add_cnc_info(self, cnc_info):
        await self._insert('cnc_info', cnc_info)

    async def add_cnc_stat(self, cnc_stat):
        await self._insert('cnc_stat', cnc_stat)

    async def add_attack_stat(self, attack):
        await self._insert('attack_stat', attack)

async def test_db_1():
    db_store = DBStore()
    await db_store.open()
    b = BotInfo('00000000','mirai','2022-02-01 15:00:09','1970-01-01 00:00:00','elf',100)
    b1 = BotInfo('00000001','mirai','2022-02-01 15:00:09','1970-01-01 00:00:00','elf',100)
    print(f'add bot:{repr(b)}')
    await db_store.add_bot(b)
    print(f'add bot:{repr(b1)}')
    await db_store.add_bot(b1)
    bots = await db_store.load_bot_info()
    for bot in bots:
        print(repr(bot))
    await db_store.close()

async def test_db_2():
    db_store = DBStore()
    await db_store.open()
    b = BotInfo('00000011','mirai','2022-02-01 15:00:09','1970-01-01 00:00:00','elf',100)
    b1 = BotInfo('00000012','mirai','2022-02-01 15:00:09','1970-01-01 00:00:00','elf',100)
    print(f'add bot:{repr(b)}')
    await db_store.add_bot(b)
    print(f'add bot:{repr(b1)}')
    await db_store.add_bot(b1) #confliction
    await db_store.close()

async def test_db_3():
    db_store = DBStore()
    await db_store.open()
    b = BotInfo('00000021','mirai','2022-02-01 15:00:09','1970-01-01 00:00:00',
                'elf',100,'ARM','L',32,'unknown',
                '2024-03-29 19:00:08','P6Y5M4DT3H2M1S',
                '2024-03-28 23:09:56','P6Y5M4DT3H10M1S')
    b1 = BotInfo('00000022','mirai','2022-02-01 15:00:09','1970-01-01 00:00:00',
                 'elf',100,'ARM','L',32,'active',
                 '2024-03-29 19:00:08','P6Y5M4DT3H2M1S',
                 '2024-03-28 23:09:56','P6Y5M4DT3H1M10S')
    print(f'add bot:{repr(b)}')
    await db_store.add_bot(b)
    print(f'add bot:{repr(b1)}')
    await db_store.add_bot(b1)
    bots = await db_store.load_bot_info([],None,2)
    for bot in bots:
        print(repr(bot))
    b1.status = 'dormant'
    print(f'update bot:{repr(b1)}')
    await db_store.update_bot_info(b1)
    bots = await db_store.load_bot_info(['unknown','active'],None,2)
    for bot in bots:
        print(repr(bot))
    bots = await db_store.load_bot_info(['unknown','dormant'],'12345678',2)
    for bot in bots:
        print(repr(bot))
    await db_store.close()

db_test_cases = {'case 1: insert and load': test_db_1,
                 'case 2: primary key confliction': test_db_2,
                 'case 3: all fields insert, update and load with filter': test_db_3}

# before doing the test, manually drop tables
async def test_db():
    print('start runing db test cases...')
    for k,v in db_test_cases.items():
        print(k)
        await v()
    print('done runing db test cases')
