#!/usr/bin/python
# coding=utf-8

from ansible.module_utils.basic import AnsibleModule
from ailib import AssistedClient


DOCUMENTATION = '''
module: ai_cluster
short_description: Handles AI clusters using ailib
description:
    - Longer description of the module
    - You might include instructions
version_added: "0.2"
author: "Karim Boumedhel, @karmab"
notes:
    - Details at https://github.com/karmab/aicli
requirements:
    - aicli python package you can grab from pypi'''

EXAMPLES = '''
- name: Create a AI cluster
  ai_cluster:
    name: myclu
    type: kubeadm
    parameters:
     masters: 3
     workers: 2

- name: Delete that cluster
  ai_cluster:
    name: myclu
    state: absent
'''


def main():
    """

    """
    argument_spec = {
        "state": {
            "default": "present",
            "choices": ['present', 'absent'],
            "type": 'str'
        },
        "url": {"type": "str", "default": "https://api.openshift.com"},
        "name": {"required": True, "type": "str"},
        "offlinetoken": {"required": False, "type": "str"},
        "parameters": {"required": False, "type": "dict"},
    }
    module = AnsibleModule(argument_spec=argument_spec)
    overrides = module.params['parameters'] if module.params['parameters'] is not None else {}
    cluster = module.params['name']
    offlinetoken = module.params['offlinetoken']
    url = module.params['url']
    ai = AssistedClient(url, offlinetoken=offlinetoken)
    clusters = [x['name'] for x in ai.list_clusters()]
    exists = True if cluster in clusters else False
    state = module.params['state']
    if state == 'present':
        if exists:
            changed = False
            skipped = True
            meta = {'result': 'skipped'}
        else:
            infraenv = f"{cluster}_infra-env"
            infraenv_overrides = overrides.copy()
            infraenv_overrides['cluster'] = cluster
            meta = ai.create_cluster(cluster, overrides)
            ai.create_infra_env(infraenv, infraenv_overrides)
            changed = True
            skipped = False
    else:
        if exists:
            meta = ai.delete_cluster(cluster)
            for infra_env in ai.list_infra_envs():
                infra_env_name = infra_env.get('name')
                associated_infra_envs = [f"{cluster}_infra-env", f"{cluster}-day2_infra-env"]
                if infra_env_name is not None and infra_env_name in associated_infra_envs:
                    infra_env_id = infra_env['id']
                    ai.delete_infra_env(infra_env_id)
            changed = True
            skipped = False
        else:
            changed = False
            skipped = True
            meta = {'result': 'skipped'}
    module.exit_json(changed=changed, skipped=skipped, meta=meta)


if __name__ == '__main__':
    main()
