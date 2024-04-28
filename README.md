# bot-tracker

A tool for tracking botnet activities.

## Commands:

- 'help' for help with commands
- 'quit' to exit

##### Bot management commands:
- list-bot: list bot information.
- start-bot: start running bot.
- stop-bot: stop running bot.

##### CnC information query:
- list-cnc: list cnc information.
- list-cnc-stat: list cnc status information.

##### Bot scheduler setting commands:
- schedinfo: show bot scheduler information.
- set-sched: set scheduler parameters.

## Configuration:
##### [tracker]
- id = 0001

##### [rate_limit]
- network_peak = 256
- network_average = 128
- network_burst = 256
- port_peak = 256
- port_average = 128
- port_burst = 256

##### [network_control]
- max_conn = 0
- allowed_tcp_ports = 80,443

##### [scheduler]
- mode = 'auto'
- checkpoint_interval = 10
- sandbox_vcpu_quota = 25
- max_sandbox_num = 20
- max_dormant_duration = 24
- cnc_probing_duration = 100

