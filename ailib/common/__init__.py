from ast import literal_eval
from base64 import b64decode, b64encode
from ipaddress import ip_network, ip_address
from urllib.request import urlopen
from urllib.parse import urlencode
import json
import os
import socket
from shutil import copy2, which
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
    if overrides.get('relocate', False):
        relocate_cidr = overrides.get('relocate_cidr', '192.168.7.0/24')
        overrides.update(get_relocate_data(relocate_cidr, overrides))
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


def create_onprem(overrides={}, debug=False):
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
        if overrides.get('keep', False):
            copy2(f"{tmpdir}/configmap.yml", '.')
            copy2(f"{tmpdir}/pod.yml", '.')
        else:
            if debug:
                print(open(f"{tmpdir}/configmap.yml").read())
                info(f"Running: podman play kube --configmap {tmpdir}/configmap.yml {tmpdir}/pod.yml")
            call(f"podman play kube --configmap {tmpdir}/configmap.yml {tmpdir}/pod.yml", shell=True)


def delete_onprem(overrides={}, debug=False):
    if which('podman') is None:
        error("You need podman to run this")
        sys.exit(1)
    if debug:
        info("Running: podman pod rm -fi assisted-installer")
    call("podman pod rm -fi assisted-installer", shell=True)


def get_relocate_data(relocate_cidr='192.168.7.0/24', overrides={}):
    sno = overrides.get('high_availability_mode', 'XXX') == "None" or overrides.get('sno', False)
    basedir = f'{os.path.dirname(get_overrides.__code__.co_filename)}/relocate'
    data = {}
    mcs = []
    network = ip_network(relocate_cidr)
    api_vip = overrides.get('api_vip') or overrides.get('api_ip')
    ingress_vip = overrides.get('ingress_vip') or overrides.get('ingress_ip')
    new_api_vip, new_ingress_vip = None, None
    if api_vip is None or (api_vip is not None and not ip_address(api_vip) in network):
        new_api_vip = str(network[-3])
        if not sno:
            warning(f"Current api vip doesnt belong to {relocate_cidr}, Setting it to {new_api_vip} instead")
            _type = 'api_ip' if 'api_ip' in overrides else 'api_vip'
            data[_type] = new_api_vip
    if ingress_vip is None or (ingress_vip is not None and not ip_address(ingress_vip) in network):
        new_ingress_vip = str(network[-4])
        if not sno:
            warning(f"Current ingress vip doesnt belong to {relocate_cidr}, Setting it to {new_ingress_vip} instead")
            _type = 'ingress_ip' if 'ingress_ip' in overrides else 'ingress_vip'
            data['ingress_ip'] = new_ingress_vip
    if overrides.get('relocate_switch', True) and new_api_vip is not None and new_ingress_vip is not None:
        info("Setting relocation switch")
        namespace_data = open(f"{basedir}/00-relocate-namespace.yaml").read()
        mcs.append({'00-relocate-namespace.yaml': namespace_data})
        sa_data = open(f"{basedir}/97-relocate-sa.yaml").read()
        mcs.append({'97-relocate-sa.yaml': sa_data})
        binding_data = open(f"{basedir}/98-relocate-binding.yaml").read()
        mcs.append({'98-relocate-binding.yaml': binding_data})
        job_template = open(f"{basedir}/99-relocate-job.yaml").read()
        registry = overrides.get('relocate_registry', True)
        olm_operators = overrides.get('olm_operators', [])
        if registry:
            waitcommand = 'kubectl get sc ocs-storagecluster-ceph-rbd'
            waitcommand = f'until [ "$({waitcommand})" != "" ] ; do sleep 5 ; done'
            waitcommand += '; kubectl patch storageclass ocs-storagecluster-ceph-rbd '
            waitcommand += '-p \'{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}\''
            storage_operator = 'lvm' if sno else 'odf'
            if storage_operator not in olm_operators:
                warning(f"Enabling {storage_operator} for relocate registry")
                olm_operators.append(storage_operator)
                data['olm_operators'] = olm_operators
        else:
            waitcommand = "kubectl get clusterversion version -o jsonpath='{.status.history[0].state}'"
            waitcommand = f'until [ "$({waitcommand})" == "Completed" ] ; do sleep 10 ; done'
        job_data = job_template % {'api_vip': api_vip, 'ingress_vip': ingress_vip, 'registry': str(registry).lower(),
                                   'waitcommand': waitcommand}
        mcs.append({'99-relocate-job.yaml': job_data})
    template = open(f"{basedir}/hack.sh").read()
    netmask = network.prefixlen
    first = str(network[1]).split('.')
    prefix, num = '.'.join(first[:-1]), first[-1]
    hack_data = template % {'netmask': netmask, 'prefix': prefix, 'num': num}
    hack_data = str(b64encode(hack_data.encode('utf-8')), 'utf-8')
    hack_template = open(f"{basedir}/hack.ign").read()
    ignition_config_override = json.dumps(yaml.safe_load(hack_template % {'data': hack_data}))
    data['ignition_config_override'] = ignition_config_override
    hint_template = open(f"{basedir}/10-node-ip-hint.yaml").read()
    hint_data = f"KUBELET_NODEIP_HINT={str(network.network_address)}"
    hint_data = str(b64encode(hint_data.encode('utf-8')), 'utf-8')
    mc_hint = hint_template % {'role': 'master', 'data': hint_data}
    mcs.append({'10-node-ip-hint-master.yaml': mc_hint})
    mc_hint = hint_template % {'role': 'worker', 'data': hint_data}
    mcs.append({'10-node-ip-hint-worker.yaml': mc_hint})
    relocate_template = open(f"{basedir}/10-relocate-ip.yaml").read()
    mc_relocate = relocate_template % {'role': 'master'}
    mcs.append({'10-relocate-ip-master.yaml': mc_relocate})
    mc_relocate = relocate_template % {'role': 'worker'}
    mcs.append({'10-relocate-ip-worker.yaml': mc_relocate})
    data['manifests'] = mcs
    return data
