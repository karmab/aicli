from ast import literal_eval
from base64 import b64decode
from urllib.request import urlopen
from urllib.parse import urlencode
import json
import os
import socket
from shutil import which
from subprocess import call
import sys
from tempfile import TemporaryDirectory
from time import time
from uuid import UUID
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import urllib.request
import yaml

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
    if paramfile is not None:
        if not os.path.exists(os.path.expanduser(paramfile)):
            error(f"Parameter file {paramfile} not found. Leaving")
            os._exit(1)
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
                elif value.startswith('{') and value.endswith('}') and not value.startswith('{\"ignition'):
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
    with open(f"{aihome}/token.txt", 'w') as f:
        f.write(token)
    return token


def confirm(message):
    message = f"{message} [y/N]: "
    try:
        _input = input(message)
        if _input.lower() not in ['y', 'yes']:
            error("Leaving...")
            sys.exit(1)
    except:
        sys.exit(1)
    return


def same_uuid(id1, id2):
    return id1.split('-')[3:] == id2.split('-')[3:]


def match_mac(host, mac):
    if ':' not in mac or 'inventory' not in host:
        return False
    found = False
    for interface in json.loads(host['inventory'])['interfaces']:
        if interface.get('mac_address', '') == mac:
            found = True
            break
    return found


def valid_uuid(uuid):
    try:
        UUID(uuid)
        return True
    except:
        return False


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    result = s.getsockname()[0]
    s.close()
    return result


def create_onprem(overrides={}):
    if which('podman') is None:
        error("You need podman to run this")
        sys.exit(1)
    with TemporaryDirectory() as tmpdir:
        with open(f"{tmpdir}/pod.yml", 'w') as p:
            pod_url = "https://raw.githubusercontent.com/openshift/assisted-service/master/deploy/podman/pod.yml"
            response = urllib.request.urlopen(pod_url)
            p.write(response.read().decode('utf-8'))
        with open(f"{tmpdir}/configmap.yml.ori", 'w') as c:
            cm_name = 'okd-configmap' if overrides.get('okd', False) else 'configmap'
            cm_url = f"https://raw.githubusercontent.com/openshift/assisted-service/master/deploy/podman/{cm_name}.yml"
            response = urllib.request.urlopen(cm_url)
            c.write(response.read().decode('utf-8'))
        ip = overrides.get('ip') or get_ip() or '192.168.122.1'
        info(f"Using ip {ip}")
        IMAGE_SERVICE_BASE_URL = f'http://{ip}:8888'
        SERVICE_BASE_URL = f'http://{ip}:8090'
        with open(f"{tmpdir}/configmap.yml", 'wt') as dest:
            for line in open(f"{tmpdir}/configmap.yml.ori", 'rt').readlines():
                if 'IMAGE_SERVICE_BASE_URL' in line:
                    dest.write(f"  IMAGE_SERVICE_BASE_URL: {IMAGE_SERVICE_BASE_URL}\n")
                elif 'SERVICE_BASE_URL:' in line:
                    dest.write(f"  SERVICE_BASE_URL: {SERVICE_BASE_URL}\n")
                else:
                    dest.write(line)
        call(f"podman play kube --configmap {tmpdir}/configmap.yml {tmpdir}/pod.yml", shell=True)


def delete_onprem(overrides={}):
    if which('podman') is None:
        error("You need podman to run this")
        sys.exit(1)
    call("podman pod rm -fi assisted-installer", shell=True)
