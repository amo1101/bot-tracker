CREATE TABLE IF NOT EXISTS bot_info (
    bot_id VARCHAR (128) PRIMARY KEY,
    family VARCHAR (32),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ,
    file_type VARCHAR (8),
    file_size INT,
    arch VARCHAR (8),
    endianness CHAR (1),
    bitness INT,
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
    bot_id VARCHAR (128),
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
    bot_id VARCHAR (128),
    cnc_ip INET,
    target INET,
    attack_type VARCHAR (16),
    attack_at TIMESTAMPTZ,
    attack_duration INTERVAL
);

-- insert 3 records for the test bot
INSERT INTO bot_info (
    bot_id,
    family,
    first_seen,
    last_seen,
    file_type,
    file_size,
    arch,
    endianness,
    bitness,
    status,
    dormant_at,
    dormant_duration,
    observe_at,
    observe_duration,
    tracker) VALUES (
    '00000001',
    'bot',
    '2024-04-01 00:00:00',
    '1970-01-01 00:00:00',
    'py',
    '1000',
    'ARM',
    'L',
    '32',
    'unknown',
    '1970-01-01 00:00:00',
    'P0Y0M0DT0H0M0S',
    '1970-01-01 00:00:00',
    'P0Y0M0DT0H0M0S',
    '');

INSERT INTO bot_info (
    bot_id,
    family,
    first_seen,
    last_seen,
    file_type,
    file_size,
    arch,
    endianness,
    bitness,
    status,
    dormant_at,
    dormant_duration,
    observe_at,
    observe_duration,
    tracker) VALUES (
    '00000002',
    'bot',
    '2024-04-01 01:00:00',
    '1970-01-01 00:00:00',
    'py',
    '1000',
    'MIPS',
    'L',
    '32',
    'unknown',
    '1970-01-01 00:00:00',
    'P0Y0M0DT0H0M0S',
    '1970-01-01 00:00:00',
    'P0Y0M0DT0H0M0S',
    '');

INSERT INTO bot_info (
    bot_id,
    family,
    first_seen,
    last_seen,
    file_type,
    file_size,
    arch,
    endianness,
    bitness,
    status,
    dormant_at,
    dormant_duration,
    observe_at,
    observe_duration,
    tracker) VALUES (
    '00000003',
    'bot',
    '2024-04-01 02:00:00',
    '1970-01-01 00:00:00',
    'py',
    '1000',
    'MIPS',
    'B',
    '32',
    'unknown',
    '1970-01-01 00:00:00',
    'P0Y0M0DT0H0M0S',
    '1970-01-01 00:00:00',
    'P0Y0M0DT0H0M0S',
    '');

