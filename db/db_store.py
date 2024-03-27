import os
import sys
import psycopg
from enum import Enum
from dataclass import dataclass, is_dataclass, fields, astuple

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
    as: str
    location: str

@dataclass
class BotInfo:
    bot_id: str
    family: str
    first_seen: str
    last_seen: str
    file_type: str
    file_size: int
    arch: str
    endianness: str
    bitness: int
    cnc_ip: str
    status: str = BotStatus.UNKNOWN.value
    dormant_at: str
    dormant_duration: str
    observe_at: str
    observe_duration: str
    tracker: str

@dataclass
class CnCStat:
    ip: str
    # could be: connected/disconnected
    status: str
    time: str

# TODO
@dataclass
class AttackStat:
    bot: str
    # could be: connected/disconnected
    target: str
    attack_type: str
    time: str
    duration: str

class DBStore:
    def __init__(self):
        self.conn = None

    async def open(self):
        self.conn = await
        psycopg.AsyncConnection.connect("""dbname=botnet_tracker
                                           user=postgres
                                           password=botnet""")
    async def close(self):
        await self.conn.close()

    def _get_format(self, field):
        fomarts = {str: '%s', int: '%d'}
        return  formats[field.type]

    async def _insert(self, tbl, data_obj):
        if is_dataclass(data_obj.__class__):
            if self.conn is not None:
                async with aconn.cursor() as acur:
                    field_names = tuple(f.name for f in
                                        fields(data_obj.__class__))
                    filed_formats = tuple(self._get_format(f) for f in
                                          fields(data_obj.__class__))
                    field_values = astuple(data_obj)
                    await acur.execute(f"INSERT INTO {tbl} {str(field_names)}
                                       {str(field_formats)}", field_values)
                    acur.commit()

    async def add_bot(self, bot):
        await self._insert('bot_info', bot)

    async def add_tracker(self, tracker):
        await self._insert('tracker_info', tracker)

    #TODO
    async def load_bot_info(self, status_list, bot_id, count, tracker):
        bots = []
        status_tuple = ()
        para = ()
        for s in status:
            status_tuple += (s,)
        if len(status_tuple) > 0:
            para += (status_tuple,)
        if bot_id is not None:
            para += (bot_id,)
        if count is not None:
            para += (count,)
        para += (tracker,)

        para = ()
        if self.conn is not None:
            async with aconn.cursor() as acur:
                await acur.execute(f"SELECT * FROM bot_info where {'status IN 
                                   %s AND' if status is not None else ''}
                                   {'bot_id = %s AND'if bot_id is not None else
                                   ''} tracker = % ORDER BY first_seen {'LIMIT
                                   %s' if count is not None else ''}", para)
                async for record in acur:
                    bots.append(BotInfo(*record))
        return bots

    async def update_bot_info(self, bot):
        if self.conn is not None:
            async with aconn.cursor() as acur:
                field_updates = tuple(f.name + '=' + self._get_format(f) for f in fields(BotInfo))
                field_values = astuple(bot)
                await acur.execute(f"UPDATE bot_info SET {str(field_updates)}
                                   WHERE bot_info.sha256 = %s",
                                   field_values + (bot.sha256,))
                acur.commit()

    async def add_cnc_info(self, cnc_info):
        await self._insert('cnc_info', cnc_info)

    async def add_cnc_stat(self, cnc_stat):
        await self._insert('cnc_stat', cnc_stat)

    async def add_attack_stat(self, attack):
        await self._insert('attack_stat', attack)

