import os
import urllib3
import hvac
import random
from base64 import b64encode
from os import urandom
import yaml
import names
import pymongo
import json
from jinja2 import Environment, FileSystemLoader

myclient = pymongo.MongoClient("mongodb://%s:%s@mongo:27017/"  % ('root', 'vaultpassword'))
mydb = myclient["vaultseed"]
vaultusers = mydb["vaultusers"]
users = []

urllib3.disable_warnings()
client = hvac.Client(url=os.environ['VAULT_ADDR'], token=os.environ['VAULT_TOKEN'], verify=False)

def generate_username():
    number = str(random.randint(1,9))
    first_initial = names.get_first_name().lower()[0]
    last_name = names.get_last_name().lower()
    username = first_initial + last_name + number
    return username

def generate_password():
    s = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()?"
    passlen = 10
    password =  "".join(random.sample(s,passlen ))
    return password

def generaterandom():
    random_bytes = urandom(32)
    token = b64encode(random_bytes).decode('utf-8')
    return token

def seed_kvv1_data(mount_point, num):
    for x in range(num):
        randomstring = generaterandom()
        hvac_secret = {
            'password': randomstring,
        }
        client.secrets.kv.v1.create_or_update_secret(path='/secret' + str(x), secret=hvac_secret, mount_point=mount_point)

def seed_kvv2_data(mount_point, dept, num):
    for x in range(num):
        randomstring = generaterandom()
        hvac_secret = {
            'password': randomstring,
        }
        client.secrets.kv.v2.create_or_update_secret(path= '/' + dept + '/secret' + str(x), secret=hvac_secret, mount_point=mount_point)

def seed_local_users(mount_point, policy, num):
    for x in range(num):
        user = {}
        username = generate_username()
        password = generate_password()
        user['username'] = username
        user['password'] = password
        users.append(user)
        client.create_userpass(username, password, policy, mount_point=mount_point)

def generate_policy(department):
    file_loader = FileSystemLoader('./')
    env = Environment(loader=file_loader)
    template = env.get_template('department.hcl.j2')
    policy_output = template.render(department=department)
    client.sys.create_or_update_policy(
        name=department,
        policy=policy_output,
    )
    return policy_output

client.sys.enable_auth_method(
    method_type='userpass',
    path='userpass',
)

file = open('reporter.hcl',mode='r')
policy = file.read()
print(policy)
file.close()

client.sys.create_or_update_policy(
    name='reporter',
    policy=policy,
)

with open("/app/orgs.yaml", 'r') as stream:
    try:
        orgs = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(exc)

depts = orgs['departments']
for dept in depts:
    number = random.randint(1,21)
    if not dept == 'common':
        generate_policy(dept)
        seed_local_users('userpass', dept, number)
    seed_kvv2_data('secret', dept, number)

x = vaultusers.insert_many(users)
print(x)
