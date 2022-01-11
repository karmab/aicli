from ast import literal_eval
from base64 import b64decode
from urllib.request import urlopen
from urllib.parse import urlencode
import json
import os
import yaml
from time import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# colors = {'blue': '36', 'red': '31', 'green': '32', 'yellow': '33', 'pink': '35', 'white': '37'}
def error(text):
    color = "31"
    print(f'\033[0;{color}m{text}\033[0;0m')


def warning(text):
    color = "33"
    print(f'\033[0;{color}m{text}\033[0;0m')


def info(text):
    color = "36"
    print(f'\033[0;{color}m{text}\033[0;0m')


def success(text):
    color = "32"
    print(f'\033[0;{color}m{text}\033[0;0m')


def get_overrides(paramfile=None, param=[]):
    """

    :param paramfile:
    :param param:
    :return:
    """
    overrides = {}
    if paramfile is not None and os.path.exists(os.path.expanduser(paramfile)):
        with open(os.path.expanduser(paramfile)) as f:
            try:
                overrides = yaml.safe_load(f)
            except:
                error(f"Couldn't parse your parameters file {paramfile}. Leaving")
                os._exit(1)
    if param is not None:
        for x in param:
            if len(x.split('=')) < 2:
                continue
            else:
                if len(x.split('=')) == 2:
                    key, value = x.split('=')
                else:
                    split = x.split('=')
                    key = split[0]
                    value = x.replace(f"{key}=", '')
                if value.isdigit():
                    value = int(value)
                elif value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                elif value == '[]':
                    value = []
                elif value.startswith('{') and value.endswith('}'):
                    value = literal_eval(value)
                elif value.startswith('[') and value.endswith(']'):
                    if '{' in value:
                        value = literal_eval(value)
                    else:
                        value = value[1:-1].split(',')
                        for index, v in enumerate(value):
                            v = v.strip()
                            value[index] = v
                overrides[key] = value
    return overrides


def get_token(token, offlinetoken=None):
    aihome = f"{os.environ['HOME']}/.aicli"
    url = 'https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token'
    if token is not None:
        segment = token.split('.')[1]
        padding = len(segment) % 4
        segment += padding * '='
        expires_on = json.loads(b64decode(segment))['exp']
        remaining = expires_on - time()
        if expires_on == 0 or remaining > 600:
            return token
    data = {"client_id": "cloud-services", "grant_type": "refresh_token", "refresh_token": offlinetoken}
    data = urlencode(data).encode("ascii")
    result = urlopen(url, data=data).read()
    page = result.decode("utf8")
    token = json.loads(page)['access_token']
    info(f"Storing new token in {aihome}/token.txt")
    with open(f"{aihome}/token.txt", 'w') as f:
        f.write(token)
    return token
