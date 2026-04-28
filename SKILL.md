---
name: aicli
description: Comprehensive guide for aicli usage. Use when deploying OpenShift clusters via the Assisted Installer API, managing hosts, infraenvs, ISOs, manifests, or performing any aicli operations.
---

# aicli User Guide

aicli is a Python CLI client for the Red Hat Assisted Installer API. It simplifies deploying OpenShift clusters by wrapping the assisted-installer service API with a straightforward command-line interface.

## Setup & Authentication

### SAAS mode (default)
Get an offline token at https://cloud.redhat.com/openshift/token, then set it:
```bash
export AI_OFFLINETOKEN=<your_token>
```

### On-premise mode
```bash
export AI_URL=http://<AI_IP>:8090
```

### Staging / Integration
```bash
aicli --staging ...     # or export AI_STAGING=true
aicli --integration ... # or export AI_INTEGRATION=true
```

### TLS
```bash
export AI_CA=<ca_content_or_path>
export AI_CERT=<cert_path>
export AI_KEY=<key_path>
```

### Installation
```bash
pip3 install aicli                          # pip
sudo dnf -y copr enable karmab/aicli && sudo dnf -y install aicli  # rpm
# container
alias aicli='podman run --net host -it --rm -e AI_OFFLINETOKEN=$AI_OFFLINETOKEN -v $HOME/.aicli:/root/.aicli -v $PWD:/workdir quay.io/karmab/aicli'
```

## Quick Reference

```bash
# Cluster lifecycle
aicli create cluster <name>              # Create cluster (+ infraenv)
aicli list cluster                       # List clusters
aicli info cluster <name>                # Cluster details
aicli update cluster <name> -P key=val   # Update cluster params
aicli start cluster <name>               # Launch install
aicli stop cluster <name>                # Reset/cancel install
aicli wait cluster <name>                # Wait for install to complete
aicli delete cluster <name>              # Delete cluster + infraenv
aicli export cluster <name>              # Export cluster params

# Hosts
aicli list hosts                         # List all hosts
aicli info host <name>                   # Host details
aicli update host <name> -P key=val      # Update hostname/role/disk
aicli wait hosts <infraenv> -n 3         # Wait for N hosts to appear
aicli start hosts <host1> <host2>        # Start day2 host install
aicli stop hosts <host1> <host2>         # Stop host install
aicli delete host <name>                 # Delete host
aicli boot hosts -P paramfile=params.yml # Boot hosts via redfish

# Infraenvs
aicli create infraenv <name>             # Create infraenv
aicli list infraenv                      # List infraenvs
aicli info infraenv <name>               # Infraenv details
aicli update infraenv <name> -P key=val  # Update infraenv
aicli delete infraenv <name>             # Delete infraenv
aicli start infraenv <name>              # Start infraenv hosts install
aicli stop infraenv <name>               # Stop infraenv hosts install

# Binding (late binding workflow)
aicli bind host <host> <cluster>         # Bind host to cluster
aicli unbind host <host>                 # Unbind host
aicli bind infraenv <infraenv> <cluster> # Bind all infraenv hosts
aicli unbind infraenv <infraenv>         # Unbind all infraenv hosts

# ISOs
aicli info iso <infraenv>                # Get discovery ISO URL
aicli download iso <infraenv>            # Download ISO locally
aicli update iso <infraenv> -P key=val   # Update discovery ISO

# Downloads / Assets
aicli download kubeconfig <cluster>      # Download kubeconfig
aicli download kubeadmin-password <cluster>  # Download kubeadmin pwd
aicli download installconfig <cluster>   # Download install-config
aicli download ignition <cluster>        # Download ignition file
aicli download discovery-ignition <infraenv> # Download discovery ignition
aicli download ipxe-script <infraenv>    # Download iPXE script
aicli download initrd <infraenv>         # Download initrd
aicli download manifests <cluster>       # Download manifests
aicli download static-network-config <infraenv> # Download static net cfg

# Manifests
aicli create manifests --dir <dir> <cluster>  # Upload manifests
aicli list manifests <cluster>                # List manifests
aicli delete manifests <cluster>              # Delete manifests

# Events & Validations
aicli list events <cluster>              # List cluster events
aicli list events -f <cluster>           # Follow events live
aicli info validation <cluster>          # Show validation status

# Keywords (discover available params)
aicli list keywords                      # All keywords
aicli list cluster-keywords              # Cluster-specific
aicli list extra-keywords                # Extra/shortcut keywords
aicli list host-keywords                 # Host-specific
aicli list infraenv-keywords             # Infraenv-specific

# Deployment (e2e workflow)
aicli create deployment --pf params.yml <name>  # Full e2e deploy
aicli scale deployment --pf params.yml <name>   # Add day2 workers

# Onprem
aicli create onprem                      # Deploy AI locally via podman
aicli delete onprem                      # Remove local AI deployment

# Service
aicli info service                       # Show AI service info

# ABI credentials
aicli create abi-creds                   # Gather ABI credentials
```

## Parameters

Parameters are passed via `-P key=value` (repeatable) or `--paramfile`/`--pf` pointing to a YAML file.

If a file named `aicli_parameters.yml` exists in the current directory, it is auto-loaded.

## Creating Clusters

### Basic cluster
```bash
aicli create cluster mycluster
```
This auto-creates an infraenv named `mycluster_infra-env`.

### With parameters
```bash
aicli create cluster -P openshift_version=4.21 -P base_dns_domain=example.com mycluster
```

### SNO (Single Node OpenShift)
```bash
aicli create cluster -P sno=true mycluster
```

### Common extra parameters

| Parameter | Meaning |
|---|---|
| api_ip | API VIP |
| ingress_ip | Ingress VIP |
| domain | Base DNS domain |
| sno | Deploy Single Node OpenShift |
| sno_disk | Disk for SNO install |
| minimal | Use minimal ISO |
| network_type | CNI plugin (OVNKubernetes, OpenshiftSDN, Calico) |
| static_network_config | NMState data for static networking |
| manifests | Directory of manifests to inject |
| pull_secret | Path to pull secret file (default: openshift_pull.json) |
| ignore_validations | Skip all validations |
| hosts | Array of host definitions for automated deployment |
| password | Add debugging user (aicli/aicli) to discovery ISO |
| registry_url | Custom registry URL (disconnected/OKD) |
| disconnected_url | Alias for registry_url |
| discovery_ignition_file | Path to custom discovery ignition |
| kernel_arguments | Custom kernel args for discovery ISO |
| infraenv | Set to false to skip infraenv creation |

### Custom install config
```bash
aicli update cluster mycluster -P installconfig="{'CPUPartitioningMode': 'AllNodes'}"
```

### Custom ignition
```bash
# Via parameter
aicli create cluster -P ignition_config_override='{"ignition":...}' mycluster
# Via file
aicli create cluster -P discovery_ignition_file=/path/to/ignition.json mycluster
```

### Custom kernel arguments
```bash
# As string (appended)
aicli create cluster -P kernel_arguments="a=xxx b=yyy" mycluster
```

## Static Networking

Provide nmstate data in parameter file under `static_network_config`:

```yaml
static_network_config:
- interfaces:
  - name: ens3
    type: ethernet
    state: up
    ipv4:
      enabled: true
      address:
      - ip: 192.168.122.100
        prefix-length: 24
      dhcp: false
  dns-resolver:
    config:
      server:
      - 192.168.122.1
  routes:
    config:
    - destination: 0.0.0.0/0
      next-hop-address: 192.168.122.1
      next-hop-interface: ens3
  mac_interface_map:
  - logical_nic_name: ens3
    mac_address: aa:bb:cc:dd:ee:ff
```

Sample files available in the `samples/` directory of the aicli repo covering static networking, bonding, and dual stack.

## Host Management

### Update hostname
```bash
aicli update host myhost -P name=newhostname
```
If multiple hosts share a cluster and match, names are assigned sequentially (name-0, name-1, ...).

### Update role
```bash
aicli update host myhost -P role=worker
```

### Specify installation disk
```bash
aicli update host myhost -P disk=sdb
```

### Skip disk formatting
```bash
aicli update host myhost -P skip_disks=[sdb,sdc]
```

### Set node labels
```bash
aicli update host myhost -P labels=[productionready,env=prod]
```

### Extra args (kernel args for install)
```bash
aicli update host myhost -P extra_args="--append-karg=rd.multipath=default"
```

### Custom ignition on first boot
```bash
aicli update host myhost -P ignition_file=/path/to/ignition.json
```

### Bulk update from parameter file
```yaml
hosts:
- name: master-0.example.com
  role: master
- name: worker-0.example.com
  role: worker
  extra_args: "ip=dhcp6"
```
```bash
aicli update hosts --pf params.yml
```

Hosts can be matched by `name`, `id` (system UUID), or `mac` (any MAC from inventory).

## Deployment Workflow (e2e)

### Single-command deployment
```bash
aicli create deployment --pf params.yml mycluster
```

### Parameter file for automated deployment with BMC
```yaml
base_dns_domain: example.com
api_vip: 192.168.122.253
ingress_vip: 192.168.122.252
download_iso_path: /var/www/html
download_iso_cmd: "chown apache.apache /var/www/html/mycluster.iso"
iso_url: http://192.168.122.1/mycluster.iso
bmc_user: admin
bmc_password: password
hosts:
- name: ctlplane-0
  bmc_url: http://192.168.122.1:8000/redfish/v1/Systems/uuid1
- name: ctlplane-1
  bmc_url: http://192.168.122.1:8000/redfish/v1/Systems/uuid2
- name: ctlplane-2
  bmc_url: http://192.168.122.1:8000/redfish/v1/Systems/uuid3
```

Without BMC info, the workflow pauses and displays the ISO URL for manual boot.

## Day2 Operations (Adding Workers)

### Create day2 cluster
```bash
aicli create cluster mycluster-day2
```
The `-day2` suffix triggers day2 mode automatically.

### Day2 workflow
1. `aicli info iso mycluster-day2` -- get discovery ISO
2. Boot new nodes with ISO
3. `aicli wait hosts mycluster-day2_infra-env -n 1` -- wait for host(s)
4. `aicli start hosts <hostname>` or `aicli start cluster mycluster-day2`

### Scale deployment (automated day2)
```bash
aicli scale deployment --pf scale_params.yml mycluster
```

## Manifests

### Upload from directory
```bash
aicli create manifests --dir /path/to/manifests mycluster
aicli create manifests --dir /path/to/manifests -o mycluster  # openshift folder
```

### Inline manifests in parameter file
```yaml
manifests:
- my-manifest.yaml: |
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: my-config
    data:
      key: value
```

## Disconnected / Custom Registry

```bash
aicli create cluster -P registry_url=myregistry.example.com:5000 mycluster
```
The CA cert is auto-fetched via openssl if reachable; otherwise provide it with `-P ca=/path/to/ca.crt`.

## Onprem Deployment

Deploy Assisted Installer locally using podman:
```bash
aicli create onprem
aicli create onprem -P ip=10.0.0.1    # specify IP manually
aicli create onprem -P keep=true      # keep configmap.yml and pod.yml
aicli delete onprem                    # clean up
```

## Typical Step-by-Step Workflow

1. **Create cluster**: `aicli create cluster mycluster -P base_dns_domain=example.com`
2. **Get ISO**: `aicli info iso mycluster` or `aicli download iso mycluster`
3. **Boot nodes** with the discovery ISO
4. **Wait for hosts**: `aicli wait hosts mycluster_infra-env -n 3`
5. **Update hosts** (if needed): `aicli update host <host> -P name=<name> -P role=<role>`
6. **Update cluster** (VIPs): `aicli update cluster mycluster -P api_ip=x.x.x.x -P ingress_ip=y.y.y.y`
7. **Start install**: `aicli start cluster mycluster`
8. **Wait**: `aicli wait cluster mycluster`
9. **Get credentials**: `aicli download kubeconfig mycluster && aicli download kubeadmin-password mycluster`

## Global Flags

| Flag | Env var | Purpose |
|---|---|---|
| `--url` / `-u` | `AI_URL` | Target API URL |
| `--offlinetoken` | `AI_OFFLINETOKEN` | SAAS offline token |
| `--token` / `-t` | `AI_TOKEN` | Direct API token |
| `--staging` / `-s` | `AI_STAGING` | Target staging env |
| `--integration` / `-i` | `AI_INTEGRATION` | Target integration env |
| `--ca` | `AI_CA` | TLS CA content or path |
| `--cert` | `AI_CERT` | TLS cert path |
| `--key` / `-k` | `AI_KEY` | TLS key path |
| `--debug` / `-d` | -- | Enable debug output |
| `--output` / `-o` | -- | Output format: json, yaml, name |

## Output Formats

Most list/info commands support `-o json`, `-o yaml`, or `-o name`:
```bash
aicli list clusters -o json
aicli info cluster mycluster -o yaml
aicli list clusters -o name
```

## Aliases

| Command | Aliases |
|---|---|
| `create` | `add` |
| `delete` | `remove` |
| `list` | `get` |
| `start` | `launch` |
| `stop` | `reset` |
| `update` | `patch` |

## Default OpenShift Version

The current default OpenShift version is **4.21**.

## Source Code Reference

The aicli source code lives in the working directory at `src/ailib/`:
- `src/ailib/__init__.py` -- `AssistedClient` class (core API logic)
- `src/ailib/cli.py` -- CLI entry point and argparse definitions
- `src/ailib/common/__init__.py` -- utility functions (get_overrides, onprem helpers)
- `src/ailib/kfish/__init__.py` -- Redfish BMC interaction
- `src/ailib/mcp.py` -- MCP server exposing aicli tools
- `samples/` -- example parameter files (static networking, bonding, dual stack, disconnected)
