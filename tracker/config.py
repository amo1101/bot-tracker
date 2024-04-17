import configparser


class TrackerConfig:
    def __init__(self):
        self.mode = None
        self.tracker_id = None
        self.tracker_id = 0
        self.mode = 0

        # rate limit
        self.network_peak = 0
        self.network_average = 0
        self.network_burst = 0
        self.port_peak = 0
        self.port_average = 0
        self.port_burst = 0

        # connection limit
        self.max_conn = 0

        # bot_runner
        self.max_runners = 0
        self.max_bot_dormant_duration = 0
        self.max_packet_analyzing_workers = 0
        self.cnc_probing_timeout = 0
        self.bot_scan_port = []

        # database
        self.db_host = ""
        self.db_port = 0
        self.db_name = ""
        self.db_user = ""
        self.db_psw = ""

        # local_bot_repo
        self.local_bot_repo_ip = ""
        self.local_bot_repo_user = ""
        self.local_bot_repo_path = ""

    def read(self, ini_file):
        config = configparser.ConfigParser()
        config.read(ini_file)
        self.tracker_id = config['tracker']['id']
        self.mode = config['tracker']['mode']
        self.network_peak = config['rate_limit']['network_peak']
        self.network_average = config['rate_limit']['network_average']
        self.network_burst = config['rate_limit']['network_burst']
        self.port_peak = config['rate_limit']['port_peak']
        self.port_average = config['rate_limit']['port_average']
        self.port_burst = config['rate_limit']['port_burst']
        self.max_conn = config['conn_limit']['max_conn']
        self.max_runners = config['bot_runner']['max_runners']
        self.max_bot_dormant_duration = config['bot_runner']['max_bot_dormant_duration']
        self.max_packet_analyzing_workers = config['bot_runner']['max_packet_analyzing_workers']
        self.cnc_probing_timeout = config['bot_runner']['cnc_probing_timeout']
        self.bot_scan_port = config['bot_runner']['bot_scan_port'].split(',')
        self.db_host = config['database']['host']
        self.db_port = config['database']['port']
        self.db_name = config['database']['dbname']
        self.db_user = config['database']['user']
        self.db_psw = config['database']['password']
        self.local_bot_repo_ip = config['local_bot_repo']['ip']
        self.local_bot_repo_user = config['local_bot_repo']['user']
        self.local_bot_repo_path = config['local_bot_repo']['path']
        

