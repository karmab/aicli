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
    print('\033[0;%sm%s\033[0;0m' % (color, text))


def warning(text):
    color = "33"
    print('\033[0;%sm%s\033[0;0m' % (color, text))


def info(text):
    color = "36"
    print('\033[0;%sm%s\033[0;0m' % (color, text))


def success(text):
    color = "32"
    print('\033[0;%sm%s\033[0;0m' % (color, text))


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
                error("Couldn't parse your parameters file %s. Leaving" % paramfile)
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
                    value = x.replace("%s=" % key, '')
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


def get_commit_rhcos_metal(commitid):
    buildurl = "https://raw.githubusercontent.com/openshift/installer/%s/data/data/rhcos.json" % commitid
    with urlopen(buildurl) as b:
        data = json.loads(b.read().decode())
        baseuri = data['baseURI']
        metal = "%s%s" % (baseuri, data['images']['metal']['path'])
        return metal


def get_latest_rhcos_metal(url='https://releases-art-rhcos.svc.ci.openshift.org/art/storage/releases/rhcos',
                           version='4.6'):
    url += "-%s" % version
    buildurl = '%s/builds.json' % url
    with urlopen(buildurl) as b:
        data = json.loads(b.read().decode())
        for build in data['builds']:
            build = build['id']
            # kernel = "%s/%s/x86_64/rhcos-%s-installer-kernel-x86_64" % (url, build, build)
            # initrd = "%s/%s/x86_64/rhcos-%s-installer-initramfs.x86_64.img" % (url, build, build)
            metal = "%s/%s/x86_64/rhcos-%s-metal.x86_64.raw.gz" % (url, build, build)
            return metal


def get_token(token, offlinetoken=None):
    aihome = "%s/.aicli" % os.environ['HOME']
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
    info("Storing new token in %s/token.txt" % aihome)
    with open("%s/token.txt" % aihome, 'w') as f:
        f.write(token)
    return token
