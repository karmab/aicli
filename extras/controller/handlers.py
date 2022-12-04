#!/usr/bin/env python3

from ailib import AssistedClient
import base64
import kopf
from logging import info as pprint, error
import os

DOMAIN = "aicli.karmalabs.local"
VERSION = "v1"


@kopf.on.startup()
def startup(logger, **kwargs):
    pprint("Injecting crds if needed")
    crdpath = 'crd.yml' if os.path.exists('crd.yml') else '/crd.yml'
    os.popen(f"kubectl apply -f {crdpath}").read()


@kopf.on.create(DOMAIN, VERSION, 'aiclideployment')
def create_deployment(meta, spec, status, namespace, logger, **kwargs):
    name = meta.get('name')
    pprint(f"Handling create on deployment {name}")
    overrides = dict(spec)
    overrides['pull_secret'] = os.environ.get('PULL_SECRET')
    if overrides['pull_secret'] is None:
        error('Missing pull secret')
        return {'result': 'Missing pull secret'}
    overrides['ssh_public_key'] = os.environ.get('PUBLIC_KEY')
    if overrides['ssh_public_key'] is None:
        error('Missing pull public key')
        return {'result': 'Missing public key'}
    url = os.environ.get('URL', 'https://api.openshift.com')
    OFFLINETOKEN = os.environ.get('OFFLINETOKEN')
    ai = AssistedClient(url, offlinetoken=OFFLINETOKEN)
    ai.create_deployment(name, overrides, force=True)
    kubeconfig = open(f"kubeconfig.{name}").read()
    kubeconfig = base64.b64encode(kubeconfig.encode()).decode("UTF-8")
    return {'result': 'success', 'kubeconfig': kubeconfig}
