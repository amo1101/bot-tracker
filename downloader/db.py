import os
import sys
import psycopg

class TrackerInfo:
    def __init__(self):
        self.id = None
        self.ip = None

class BotInfo:
    def __init__(self, sha256, family, first_seen, last_seen, file_type, file_size):
        self.sha256 = sha256
        self.family = family
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.file_type = file_type
        self.file_size = file_size
        self.arch = None
        self.endianness = None
        self.bitness = None
        # bot status: null/dormant/active/paused/stopped/error
        # initial state null
        self.status = 'null'
        # allow dormant for a max_duration
        # dormant_duration accured when bot is dormat
        # dormant -> active, dormant_duration is cleared
        # when paused/stopped, dormant_duration is kept
        self.dormant_start = None
        self.dormant_duration = None
        self.observe_start = None
        self.observe_duration = None
        self.tracker = 0

class DBStore:
    def __init__(self):
        self.bots = []

    # TODO: rebalance if tracker added or removed
    def _rebalance(self):
        pass

    def load_tracker(self, bot_info):
        pass

    def add_bot(self, bot_info):
        self.bots.append(bot_info)

    def persist(self):
        _rebalance()
        with psycopg.connect("dbname=test user=postgres password=test") as conn:
            with conn.cursor() as cur:
                for bot in self.bots:
                    cur.execute("""insert into bot_info (
                                sha256,
                                family,
                                first_seen,
                                last_seen,
                                file_type,
                                file_size,
                                arch,
                                endianness,
                                bitness,
                                status,
                                dormant_start,
                                dormant_duration,
                                observe_start,
                                observe_duration
                                tracker) values (
                                %s,%s,s%)
                                """, (
                                bot.sha256,
                                bot.family,
                                bot.first_seen,
                                bot.file_type,
                                bot.file_size,
                                bot.arch,
                                bot.endianness,
                                bot.bitness,
                                bot.status,
                                bot.dormant_start,
                                bot.dormant_duration,
                                bot.observe_start,
                                bot.observe_duration
                                bot.tracker))
            conn.commit()

