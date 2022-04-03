#!/usr/bin/python
# coding=utf-8

from ansible.module_utils.basic import AnsibleModule
from ailib import AssistedClient


DOCUMENTATION = '''
module: ai_host_info
short_description: Retrieve information about one host using ailib
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
- name: Get info about host
  ai_host_info:
    name: myhost
 register: result
'''


def main():
    """

    """
    argument_spec = {
        "url": {"type": "str", "default": "https://api.openshift.com"},
        "name": {"required": True, "type": "str"},
        "offlinetoken": {"required": False, "type": "str"},
    }
    module = AnsibleModule(argument_spec=argument_spec)
    host = module.params['name']
    offlinetoken = module.params['offlinetoken']
    url = module.params['url']
    ai = AssistedClient(url, offlinetoken=offlinetoken)
    meta = ai.info_host(host)
    module.exit_json(changed=False, **meta)


if __name__ == '__main__':
    main()
