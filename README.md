# bot-tracker
Tracking botnet activities

# setup for sandbox scp downloading of bot from malware repo server
1 sandbox key generation: dropbearkey -f sandbox_key -t ed25519
2 add server pub key to known_hosts on sandbox /root/.ssh/known_hosts
3 add sandbox pub key to authorized_keys on server: ~/.ssh/authorized_keys
