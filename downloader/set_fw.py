import subprocess

en_command = [
    ['iptables', '-P', 'INPUT', 'ACCEPT'],
    ['iptables', '-P', 'OUTPUT', 'ACCEPT'],
    ['iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'],
    ['iptables', '-A', 'OUTPUT', '-d', 'mb-api.abuse.ch', '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'],
    ['iptables', '-P', 'INPUT', 'DROP'],
    ['iptables', '-P', 'OUTPUT', 'DROP']
]

de_command = [
    ['iptables', '-D', 'OUTPUT', '-d', 'mb-api.abuse.ch', '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'],
    ['iptables', '-D', 'OUTPUT', '-p', 'udp', '--dport', '53', '-j', 'ACCEPT']
]

def enable_bazzar_access():
    for cmd in en_command:
        subprocess.run(cmd, check=True)

def disable_bazzar_access():
    for cmd in de_command:
        subprocess.run(cmd, check=True)



