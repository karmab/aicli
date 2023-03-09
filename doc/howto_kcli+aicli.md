This document indicates how to use kcli and aicli together to run a full deployment on virtual machines

# Requisites

- kcli installed and configured (no configuration is needed if running locally as root user)
- aicli installed and properly configured (with a valid offline token and pull secret)
- a virtualization provider (typically libvirt but vsphere or rhev also work)
- apache running locally

# Infrastructure

## Ksushy

We enable first ksushy service to ease interacting with vms through redfish

```
kcli create sushy-service
```

## Network (optional)

We can create a specific libvirt network if needed

```
kcli create network -c 192.168.127.0/24 -P dhcp_start=192.168.127.2 -P dhcp_end=192.168.127.249 myclu-net
```

## Vms

We then create as many vms as wanted 

```
kcli create vm -P start=false -P memory=20480 -P numcpus=16 -P disks=[200] -P user=core -P uefi=true -P nets=[myclu-net] --count 3 myclu-node
```

# Cluster 

We prepare a parameter file for aicli that we will name `myclu_parameters.yml`

```
base_dns_domain: karmalabs.corp
api_vip: 192.168.127.251
ingress_vip: 192.168.127.250
bmc_user: admin
bmc_password: password
hosts:
- name: myclu-node-0
  bmc_url: http://192.168.122.1:9000/redfish/v1/Systems/local/myclu-node-0
- name: myclu-node-1
  bmc_url: http://192.168.122.1:9000/redfish/v1/Systems/local/myclu-node-1
- name: myclu-node-2
  bmc_url: http://192.168.122.1:9000/redfish/v1/Systems/local/myclu-node-2
```

We can then launch deployment with

```
aicli create deployment --pf myclu_parameters.yml myclu
```
