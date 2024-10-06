import os
import json
import argparse

# CLIs
auth_cli = 'AuthApp'
attest_cli = 'AttestApp'
user_cli = 'UserApp'

# File Names
auth_config_file = 'config_auth'
attest_config_file = 'config_attest'
user_config_file = 'config_user'

# Ports
consensus_base_port = 60000
epid_base_port = 61000
attest_base_port = 62000
user_base_port = 63000

config_root_dir = os.getcwd()

cli_config = {
    auth_cli: auth_config_file,
    attest_cli: attest_config_file,
    user_cli: user_config_file
}


def get_consensus_peers(config: dict) -> list:
    peers = []
    total_id = 0
    for addr in config:
        for i in range(config[addr]):
            peers.append(f'{addr}:{consensus_base_port + i}')
            total_id += 1
    return peers


def get_user_peers(config: dict) -> list:
    peers = []
    total_id = 0
    for addr in config:
        for i in range(config[addr]):
            peers.append(f'{addr}:{user_base_port + i}')
            total_id += 1
    return peers


def generate(ignore_trust: bool, use_dcap: bool, threads: int):
    generated = dict()
    consensus_peers = get_consensus_peers(peer_config)
    user_peers = get_user_peers(peer_config)
    total_id = 1
    for addr in peer_config:
        for i in range(peer_config[addr]):
            if current_config['ip'] != addr or current_config['id'] != total_id:
                total_id += 1
                continue
            cp = consensus_peers.copy()
            cp.remove(f'{addr}:{consensus_base_port + i}')
            up = user_peers.copy()
            up.remove(f'{addr}:{user_base_port + i}')
            generated[auth_cli] = {
                '-c': consensus_base_port + i,
                '-e': epid_base_port + i,
                '-p': " ".join(cp),
                '-i': total_id,
                '-t': threads
            }
            if ignore_trust:
                generated[auth_cli]['--ignore_trust'] = 1
            if use_dcap:
                generated[auth_cli]['--use_dcap'] = 1
            generated[attest_cli] = {
                '-a': attest_base_port + i,
                '-s': '127.0.0.1',
                '-e': epid_base_port + i,
                '-t': threads
            }
            if ignore_trust:
                generated[attest_cli]['--ignore_trust'] = 1
            if use_dcap:
                generated[attest_cli]['--use_dcap'] = 1
            generated[user_cli] = {
                '-a': attest_base_port + i,
                '-u': user_base_port + i,
                '-p': " ".join(up),
                '-i': total_id
            }
            total_id += 1
    for type in generated:
        ini_name = f'{cli_config[type]}.ini'
        print(f'./{type} --config {config_root_dir}/{ini_name}')
        with open(ini_name, 'w', encoding='utf8') as fp:
            fp.writelines([f'{key} = {value}\n' for key, value in generated[type].items()])


parser = argparse.ArgumentParser()
parser.add_argument('--ignore_trust', type=bool, dest='ignore_trust', default=False, required=False)
parser.add_argument('--use_dcap', type=bool, dest='use_dcap', default=False, required=False)
parser.add_argument('-t', '--threads', type=int, dest='threads', default=3, required=False)
parser.add_argument('-p', '--peers_json', type=str, dest='peers_json_name', default='peers.json', required=False)
parser.add_argument('-c', '--current_json', type=str, dest='current_json_name', default='current.json', required=False)
args = parser.parse_args()

# Peers
'''
{
    "127.0.0.1": 1
}
'''
with open(args.peers_json_name, 'r') as f:
    peer_config = json.load(f)

# Current
'''
{
    "ip": "127.0.0.1",
    "id": 0
}
'''
with open(args.current_json_name, 'r') as f:
    current_config = json.load(f)

if __name__ == '__main__':
    generate(args.ignore_trust, args.use_dcap, args.threads)
