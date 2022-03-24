#!/usr/bin/python
# coding=utf-8

from ansible.module_utils.basic import AnsibleModule
from ailib import AssistedClient


DOCUMENTATION = '''
module: ai_infraenv
short_description: Handles AI infraenvs using ailib
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
- name: Create an AI infraenv
  ai_infraenv:
    name: myinfraenv
    parameters:
     masters: 3
     workers: 2

- name: Delete that cluster
  ai_infraenv:
    name: myinfraenv
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
    infraenv = module.params['name']
    offlinetoken = module.params['offlinetoken']
    url = module.params['url']
    ai = AssistedClient(url, offlinetoken=offlinetoken)
    infraenvs = [x['name'] for x in ai.list_infra_envs()]
    exists = True if infraenv in infraenvs else False
    state = module.params['state']
    changed, skipped = True, False
    if state == 'present':
        if exists:
            changed, skipped = False, True
            meta = {'result': 'skipped'}
        else:
            meta = ai.create_infra_env(infraenv, overrides)
    else:
        if exists:
            meta = ai.delete_infra_env(infraenv)
        else:
            changed, skipped = False, True
            meta = {'result': 'skipped'}
    module.exit_json(changed=changed, skipped=skipped, meta=meta)


if __name__ == '__main__':
    main()
