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
    ip VARCHAR (32),
    port INT,
    bot_id VARCHAR (128),
    domain VARCHAR (128),
    asn INT,
    location VARCHAR (32)
);

CREATE TABLE IF NOT EXISTS attack_info (
    bot_id VARCHAR (128),
    cnc_ip VARCHAR (32),
    cnc_port INT,
    attack_type VARCHAR (32),
    time TIMESTAMPTZ,
    duration INTERVAL,
    target VARCHAR,
    protocol VARCHAR,
    layers VARCHAR,
    src_port VARCHAR,
    dst_port VARCHAR,
    spoofed VARCHAR(8),
    packet_num BIGINT,
    total_bytes BIGINT,
    pps BIGINT,
    pps_max BIGINT,
    bandwidth BIGINT,
    bandwidth_max BIGINT
);

-- insert records for the test bot
DO $$
DECLARE
    bid INTEGER := 1;
    cnt INTEGER := 0;
BEGIN
    FOR bid IN 1..cnt LOOP
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
            'bot'||CAST(bid AS TEXT),
            'test',
	    '2024-04-01 00:00:00'::timestamp + INTERVAL '1 hour' * (bid - 1),
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
    END LOOP;
END $$;
