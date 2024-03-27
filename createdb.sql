CREATE TABLE IF NOT EXISTS bot_info (
    bot_id VARCHAR (32) PRIMARY KEY,
    family VARCHAR (32),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ,
    file_type VARCHAR (8),
    file_size INT,
    arch VARCHAR (8),
    endianness CHAR (1),
    bitness INT,
    cnc_ip INET [],
    status VARCHAR (16),
    dormant_at TIMESTAMPTZ,
    dormant_duration INTERVAL,
    observe_at TIMESTAMPTZ,
    observe_duration INTERVAL,
    tracker VARCHAR (16)
);

CREATE TABLE IF NOT EXISTS cnc_info (
    ip INET PRIMARY KEY,
    port INT,
    domain VARCHAR (128),
    asn INT,
    location VARCHAR (32)
);

CREATE TABLE IF NOT EXISTS cnc_stat (
    ip INET PRIMARY KEY,
    status VARCHAR (16),
    update_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS attack_stat (
    bot_id VARCHAR (32),
    cnc_ip INET,
    target INET,
    attack_type VARCHAR (16),
    attack_at TIMESTAMPTZ,
    attack_duration INTERVAL
);
