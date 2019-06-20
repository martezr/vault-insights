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

client = hvac.Client(url=os.environ['VAULT_ADDR'], verify=False)
client.auth_userpass(username="vaultreporter",password="password")
json_log_file = "/opt/vault/log/secrets.log"

def getkv2secretsnum(mountpoint):
    """Retrieve the number of secrets for a KV V2 secrets backend
    :param mountpoint: The Vault mount point for the KV V2 secrets backend.
    :type mountpoint: str
    :return: The number of total secrets, type of secrets backend
    and secrets per subfolder.
    :rtype: dict
    """
    try:
        secrets = client.secrets.kv.v2.list_secrets(path='', mount_point=mountpoint)
    except hvac.exceptions.InvalidPath:
        print("There are no secrets configured on the %s mount point. Empty secrets backends are not supported" % mountpoint)
        os._exit(1)
    except hvac.exceptions.Forbidden:
        print("The current Vault token does not have the appropriate permissions to access the %s mount point." % mountpoint)
        os._exit(1)

    total_secrets = 0
    json_output = {}
    json_output['secrets'] = {}
    all_secrets = secrets['data']['keys']
    for secret_path in all_secrets:
        if '/' in secret_path:
            nested_secrets = client.secrets.kv.v2.list_secrets(path=secret_path, mount_point=mountpoint)
            json_output['secrets'][mountpoint + secret_path] = len(nested_secrets['data']['keys'])
            json_output['secrets'][mountpoint + secret_path] = {}
            json_output['secrets'][mountpoint + secret_path]['data'] = []
            json_output['secrets'][mountpoint + secret_path]['secrets'] = len(nested_secrets['data']['keys'])
            suboutput = nested_secrets['data']['keys']
            for stuff in suboutput:
                secret_metadata = {}
                update_time = client.secrets.kv.v2.read_secret_metadata(path=secret_path + stuff, mount_point=mountpoint)
                secret_metadata['update_time'] = update_time['data']['updated_time']
                secret_metadata['path'] = mountpoint + secret_path + stuff
                json_output['secrets'][mountpoint + secret_path]['data'].append(secret_metadata)
            total_secrets += len(nested_secrets['data']['keys'])
        else:
            json_output['secrets'][mountpoint + secret_path] = {}
            json_output['secrets'][mountpoint + secret_path]['data'] = []
            secret_metadata = {}
            update_time = client.secrets.kv.v2.read_secret_metadata(path=secret_path, mount_point=mountpoint)
            secret_metadata['update_time'] = update_time['data']['updated_time']
            secret_metadata['path'] = mountpoint + secret_path
            json_output['secrets'][mountpoint + secret_path]['data'].append(secret_metadata)
            json_output['secrets'][mountpoint + secret_path]['secrets'] = 1
            total_secrets += 1
    json_output['total_secrets'] = total_secrets
    json_output['type'] = "kv2"
    json_output['path'] = mountpoint
    json_data = json.dumps(json_output)
    f = open(json_log_file, "a")
    f.write(json_data + '\n')
    f.close()
    return json_output


def getkv1secretsnum(mountpoint):
    """Retrieve the number of secrets for a KV V1 secrets backend
    :param mountpoint: The Vault mount point for the KV V1 secrets backend.
    :type mountpoint: str
    :return: The number of total secrets, type of secrets backend and secrets per subfolder.
    :rtype: dict
    """
    try:
        secrets = client.secrets.kv.v1.list_secrets(path='', mount_point=mountpoint)
    except hvac.exceptions.InvalidPath:
        print("There are no secrets configured on the %s mount point. Empty secrets backends are not supported" % mountpoint)
        os._exit(1)
    except hvac.exceptions.Forbidden:
        print("The current Vault token does not have the appropriate permissions to access the %s mount point." % mountpoint)
        os._exit(1)

    total_secrets = 0
    json_output = {}
    json_output['secrets'] = {}
    all_secrets = secrets['data']['keys']
    for secret_path in all_secrets:
        if '/' in secret_path:
            nested_secrets = client.secrets.kv.v1.list_secrets(path=secret_path, mount_point=mountpoint)
            json_output['secrets'][mountpoint + secret_path] = {}
            json_output['secrets'][mountpoint + secret_path]['data'] = []
            json_output['secrets'][mountpoint + secret_path]['secrets'] = len(nested_secrets['data']['keys'])
            total_secrets += len(nested_secrets['data']['keys'])
        else:
            json_output['secrets'][mountpoint + secret_path] = {}
            json_output['secrets'][mountpoint + secret_path]['data'] = []
            json_output['secrets'][mountpoint + secret_path]['secrets'] = 1
            total_secrets += 1
    json_output['total_secrets'] = total_secrets
    json_output['type'] = "kv1"
    json_output['path'] = mountpoint
    json_data = json.dumps(json_output)
    f = open(json_log_file, "a")
    f.write(json_data + '\n')
    f.close()
    return json_output


"""
    Iterate through available secrets backends and
    generate statical data.
"""
secrets_engines = client.sys.list_mounted_secrets_engines()['data']
output_data = {}
for key, value in secrets_engines.items():
    if value['type'] == 'kv':
        if value['options']['version'] == "1":
            getkv1secretsnum(key.strip('/'))
        elif value['options']['version'] == "2":
            getkv2secretsnum(key.strip('/'))
