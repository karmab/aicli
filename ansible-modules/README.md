# ansible-kcli-modules

Provides access to the latest release of the kcli modules. 

Include this role in a playbook, and any other plays, roles, and includes will have access to the modules.

The modules are found in the [library folder](./library)

## Requirements

- Ansible
- [kcli](https://github.com/karmab/kcli)

## Installation and use

Use the Galaxy client to install the role:

```
$ ansible-galaxy install karmabs.kcli-modules
```

Once installed, add it to a playbook:

```
---
- hosts: localhost
  remote_user: root
  roles:
    - role: karmab.kcli-modules
```

Because the role is referenced, the `hello-underworld` role is able to make use of the kcli modules
For single tasks, you can also use `import_role`


```
---
- hosts: localhost
  remote_user: root
  tasks:
    - import_role:
        name: karmab.kcli-modules
    - name: Create a vm
      kvirt_vm:
        name: taitibob
        state: present
        profile: centos8stream
        parameters:
         memory: 2048
```

### Role parameters

install_kcli
> Set to true, if you want kcli installed. Defaults to false

### How to use 

The following modules are available

- kvirt_vm
- kvirt_info
- kvirt_plan
- kvirt_product
- kvirt_cluster

For all of them, apart from mandatory parameters, you can provide a parameters dict with all your parameters

#### kvirt_vm

```
  - name: Create vm tahitibob from centos8stream image and forcing memory to be 2G
    kvirt_vm:
      name: tahitibob
      state: present
      #profile: centos8stream
      parameters:
       memory: 2048
    register: result
  - debug: var=result
```

|Parameter   |Required |Default Value         |
|------------|---------|----------------------|
|name        |true     |                      |
|client      |false    |                      |
|image       |false    |                      |
|profile     |false    |                      |
|parameters  |false    |Empty dict            |

#### kvirt_info

```
- name: Get ip from vm tahitibob
  kvirt_info:
    name: tahitibob
  register: result
- debug: var=result.meta.ip
```

|Parameter   |Required |Default Value         |
|------------|---------|----------------------|
|name        |true     |                      |
|client      |false    |                      |
|fields      |false    |Empty list            |
|parameters  |false    |Empty dict            |

#### kvirt_plan

```
- name: Launch plan wilibonka from plan file myplan.yml
  kvirt_plan:
    name: wilibonka
    inputfile: myplan.yml
  register: result
- debug: var=result
```

|Parameter   |Required |Default Value         |
|------------|---------|----------------------|
|name        |true     |                      |
|client      |false    |                      |
|inputfile   |false    |                      |
|parameters  |false    |Empty dict            |

#### kvirt_product

```
- name: Deploy product origin, provided there is a kcli repo providing it
  kvirt_product:
    name: microshift
    product: microshift
```

|Parameter   |Required |Default Value         |
|------------|---------|----------------------|
|name        |true     |                      |
|client      |false    |                      |
|product     |true     |                      |
|repo        |false    |                      |
|parameters  |false    |Empty dict            |

#### kvirt_cluster

```
- name: Create a k8s cluster
  kvirt_cluster:
    state: absent
    name: myclu
    type: kubeadm
    parameters:
     masters: 3
     workers: 2
  register: result
- debug: var=result
```

|Parameter   |Required |Default Value         |
|------------|---------|----------------------|
|name        |true     |                      |
|client      |false    |                      |
|type        |false    |generic               |
|parameters  |false    |Empty dict            |

## License

Apache V2
