#!/usr/local/bin/python

import os
import urllib3
import hvac
import json

urllib3.disable_warnings()

try:
    os.environ["VAULT_ADDR"]
except Exception:
    print("The VAULT_ADDR environment must be set.")
    os._exit(1)

token = ""
client = hvac.Client(url=os.environ['VAULT_ADDR'], verify=False, token=token)

auth_methods = client.sys.list_auth_methods()['data']

approle_mounts = []
userpass_mounts = []
ldap_mounts = []

# Iterate over enable auth methods
for key, value in auth_methods.items():
    if value['type'] == 'userpass':
        userpass_mounts.append(key.strip('/'))
    elif value['type'] == 'approle':
        approle_mounts.append(key.strip('/'))
    elif value['type'] == 'ldap':
        ldap_mounts.append(key.strip('/'))

def approle_stats(path):
    output = client.list('auth/' + path + '/role')
    roles = output['data']['keys']

    for role in roles:
        role_path = 'auth/' + path + '/role/' + role
        output = client.read(role_path)
        assigned_policies = output['data']['policies']
        for policy in assigned_policies:
            if policy not in policies:
                assignment_data['orphan_assignments'][role] = policy
                break
            assignment_data[policy]['total_assignments'] += 1
            assignment_data[policy]['assignments'].append(path + '_' + role)

def userpass_stats(path):
    output = client.list('auth/' + path + '/users')
    users = output['data']['keys']

    for user in users:
        user_path = 'auth/' + path + '/users/' + user
        output = client.read(user_path)
        assigned_policies = output['data']['policies']
        for policy in assigned_policies:
            if policy not in policies:
                assignment_data['orphan_assignments'][user] = policy
                break
            assignment_data[policy]['total_assignments'] += 1
            assignment_data[policy]['assignments'].append(path + '_' + user)

assignment_data = {}
assignment_data['orphan_assignments'] = {}

policies = client.sys.list_policies()['data']['policies']
for policy in policies:
    assignment_data[policy] = {}
    assignment_data[policy]['total_assignments'] = 0
    assignment_data[policy]['assignments'] = []

for mount in approle_mounts:
    approle_stats(mount)

for mount in userpass_mounts:
    userpass_stats(mount)

print(json.dumps(assignment_data))
