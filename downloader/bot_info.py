import os
import sys

class BotInfo:
    def __init__(self):
        self.sha256 = None
        self.family = None
        self.first_seen = None
        self.last_seen = None
        self.file_type = None
        self.file_size = None
        self.arch = None
        self.endianness = None
        self.addr_len = None
        # bot status: null/dormant/active/paused/stopped
        # initial state null
        self.status = None
        # allow dormant for a max_duration
        # dormant_duration accured when bot is dormat
        # dormant -> active, dormant_duration is cleared
        # when paused/stopped, dormant_duration is kept
        self.dormant_start = None
        self.dormant_duration = None
        self.observe_start = None
        self.observe_duration = None

class BotInfoStore:
    def __init__(self):
        self.bots = []

    def add(self, bot_info):
        self.bots.append(bot_info)

    def persist(self):
        pass
