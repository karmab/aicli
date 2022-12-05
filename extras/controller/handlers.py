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
    overrides['pull_secret'] = os.environ.get('PULL_SECRET').strip()
    if overrides['pull_secret'] is None:
        error('Missing pull secret')
        return {'result': 'Missing pull secret'}
    overrides['ssh_public_key'] = os.environ.get('PUBLIC_KEY').strip()
    if overrides['ssh_public_key'] is None:
        error('Missing public key')
        return {'result': 'Missing public key'}
    url = os.environ.get('URL', 'https://api.openshift.com')
    OFFLINETOKEN = os.environ.get('OFFLINETOKEN').strip()
    ai = AssistedClient(url, offlinetoken=OFFLINETOKEN)
    ai.create_deployment(name, overrides, force=True)
    kubeconfig = open(f"kubeconfig.{name}").read()
    kubeconfig = base64.b64encode(kubeconfig.encode()).decode("UTF-8")
    return {'result': 'success', 'kubeconfig': kubeconfig}


@kopf.on.delete(DOMAIN, VERSION, 'aiclideployment')
def delete_deployment(meta, spec, status, namespace, logger, **kwargs):
    name = meta.get('name')
    pprint(f"Handling create on deployment {name}")
    url = os.environ.get('URL', 'https://api.openshift.com')
    OFFLINETOKEN = os.environ.get('OFFLINETOKEN')
    ai = AssistedClient(url, offlinetoken=OFFLINETOKEN)
    for clu in ai.list_clusters():
        if clu['name'] == name:
            ai.delete_cluster(name)
            break
    for infra_env in ai.list_infra_envs():
        infra_env_name = infra_env.get('name')
        associated_infra_envs = [f"{name}_infra-env", f"{name}-day2_infra-env"]
        if infra_env_name is not None and infra_env_name in associated_infra_envs:
            infra_env_id = infra_env['id']
            ai.delete_infra_env(infra_env_id)
    return {'result': 'success'}
