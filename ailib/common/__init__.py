from ast import literal_eval
from base64 import b64decode
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
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import urllib.request
import yaml

# colors = {'blue': '36', 'red': '31', 'green': '32', 'yellow': '33', 'pink': '35', 'white': '37'}


def error(text):
    color = "31"
    print(f'\033[0;{color}m{text}\033[0;0m')


def warning(text, quiet=False):
    if quiet:
        return
    color = "33"
    print(f'\033[0;{color}m{text}\033[0;0m')


def info(text, quiet=False):
    if quiet:
        return
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


def match_mac(host, mac):
    if ':' not in mac or 'inventory' not in host:
        return False
    found = False
    for interface in json.loads(host['inventory'])['interfaces']:
        if interface.get('mac_address', '') == mac:
            found = True
            break
    return found


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    result = s.getsockname()[0]
    s.close()
    return result


def create_onprem(overrides={}, debug=False):
    onprem_version = overrides.get('onprem_version', 'latest')
    if which('podman') is None:
        error("You need podman to run this")
        sys.exit(1)
    with TemporaryDirectory() as tmpdir:
        ip = overrides.get('onprem_ip') or get_ip() or '192.168.122.1'
        ipv6 = ':' in ip
        info(f"Using ip {ip}")
        if os.path.exists('pod.yml'):
            info("Using existing pod.yml")
            copy2("pod.yml", tmpdir)
        else:
            with open(f"{tmpdir}/pod.yml", 'w') as p:
                pod_url = "https://raw.githubusercontent.com/openshift/assisted-service/master/deploy/podman/"
                pod_url += "pod-persistent.yml" if overrides.get('persistent', False) else 'pod.yml'
                response = urllib.request.urlopen(pod_url).read().decode('utf-8')
                response = response.replace('latest', onprem_version).replace(f'postgresql-12-c8s:{onprem_version}',
                                                                              'postgresql-12-c8s:latest')
                restart_policy = overrides.get('restart_policy')
                if restart_policy is not None and restart_policy == 'Always':
                    response = response.replace('Never', 'Always')
                p.write(response)
        if os.path.exists('configmap.yml'):
            info("Using existing configmap.yml")
            copy2("configmap.yml", tmpdir)
        else:
            with open(f"{tmpdir}/configmap.yml.ori", 'w') as c:
                cm_name = 'okd-configmap' if overrides.get('okd', False) else 'configmap'
                cm_url = "https://raw.githubusercontent.com/openshift/assisted-service/master/deploy/podman/"
                cm_url += f"{cm_name}.yml"
                response = urllib.request.urlopen(cm_url).read().decode('utf-8')
                if ipv6:
                    response = response.replace('127.0.0.1:8090', f'"[{ip}]:8090"')
                c.write(response)
            if ipv6 and '[' not in ip:
                ip = f"[{ip}]"
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
        if 'ocp_release_image' in overrides:
            info("Patching deployment for disconnected")
            try:
                from yaml import safe_load, safe_dump
            except:
                error("PyYAML is required for patching deployment")
                sys.exit(1)
            arch = os.uname().machine
            ocp_release_image = overrides['ocp_release_image']
            version_long = ocp_release_image.split(':')[-1].split('-')[0]
            openshift_version = f"4.{version_long.split('.')[1]}"
            with open(f'{tmpdir}/configmap.yml', 'r') as f:
                cm = safe_load(f)
            data = cm['data']
            release_images = [{'openshift_version': openshift_version, 'cpu_architecture': arch,
                               'cpu_architectures': [arch], 'url': ocp_release_image, 'version': version_long}]
            data['RELEASE_IMAGES'] = json.dumps(release_images, indent=None, separators=(',', ':'))
            os_images = safe_load(data['OS_IMAGES'])
            os_images = [i for i in os_images if i['openshift_version'] == openshift_version and
                         i['cpu_architecture'] == arch]
            data['OS_IMAGES'] = json.dumps(os_images, indent=None, separators=(',', ':'))
            registry = ocp_release_image.split('/')[0]
            data['INSTALLER_IMAGE'] = f'{registry}/edge-infrastructure/assisted-installer:latest'
            data['AGENT_DOCKER_IMAGE'] = f'{registry}/edge-infrastructure/assisted-installer-agent:latest'
            data['CONTROLLER_IMAGE'] = f'{registry}/edge-infrastructure/assisted-installer-controller:latest'
            cm['data'] = data
            with open(f'{tmpdir}/configmap.yml', 'w') as f:
                safe_dump(cm, f, default_flow_style=False, encoding='utf-8', allow_unicode=True)
            with open(f'{tmpdir}/pod.yml', 'r') as f:
                pod = safe_load(f)
            spec = pod['spec']
            spec['containers'][-1]['volumeMounts'] = [{'mountPath': '/etc/pki/ca-trust/extracted/pem:Z',
                                                       'name': 'certs'}]
            spec['volumes'] = [{'name': 'certs', 'hostPath': {'path': "/etc/pki/ca-trust/extracted/pem",
                                                              "type": "Directory"}}]
            if os.path.exists('containers'):
                cwd = os.getcwd()
                spec['containers'][-1]['volumeMounts'].append({'mountPath': '/etc/containers:Z', 'name': 'containers'})
                new_entry = {'name': 'containers', 'hostPath': {'path': f"{cwd}/containers", "type": "Directory"}}
                spec['volumes'].append(new_entry)
            pod['spec'] = spec
            with open(f'{tmpdir}/pod.yml', 'w') as f:
                safe_dump(pod, f, default_flow_style=False, encoding='utf-8', allow_unicode=True)
        if overrides.get('keep', True):
            copy2(f"{tmpdir}/configmap.yml", '.')
            copy2(f"{tmpdir}/pod.yml", '.')
        if debug:
            print(open(f"{tmpdir}/configmap.yml").read())
            print(open(f"{tmpdir}/pod.yml").read())
        if ipv6:
            cmd = "podman network create --subnet fd00::1:8:0/112 --gateway 'fd00::1:8:1' --ipv6 assistedv6"
            info(f"Running: {cmd}")
            call(cmd, shell=True)
        podman = 'podman'
        if 'KUBERNETES_SERVICE_PORT' in os.environ:
            podman += ' --storage-driver vfs'
        args = '--replace'
        if ipv6:
            args += ' --network assistedv6'
        cmd = f"{podman} play kube {args} --configmap {tmpdir}/configmap.yml {tmpdir}/pod.yml"
        info(f"Running: {cmd}")
        call(cmd, shell=True)


def delete_onprem(overrides={}, debug=False):
    if which('podman') is None:
        error("You need podman to run this")
        sys.exit(1)
    if debug:
        info("Running: podman pod rm -fi assisted-installer")
    call("podman pod rm -fi assisted-installer", shell=True)


def create_creds(cluster):
    jsonfile = f"{cluster}/.openshift_install_state.json"
    if not os.path.exists(jsonfile):
        error(f"{jsonfile} Not found")
        return
    with open(jsonfile, "r", encoding="utf-8") as f:
        data = json.load(f)
    result = next((file["contents"]["source"] for file in data["*image.Ignition"]["Config"]["storage"]["files"]
                   if file["path"] == "/usr/local/share/assisted-service/assisted-service.env"), None)
    if result is not None:
        for line in b64decode(result.split(",", 1)[-1]).decode('utf-8').split('\n'):
            if line.startswith('AGENT_AUTH_TOKEN'):
                AI_TOKEN = line.split('=')[1].strip()
                call(f"echo export AI_TOKEN={AI_TOKEN} >> {os.environ.get('HOME', '/root')}/.bashrc", shell=True)


def container_mode():
    return True if os.path.exists("/i_am_a_container") and os.path.exists('/workdir') else False
