import argparse
from argparse import RawDescriptionHelpFormatter as rawhelp
from ailib.common import get_overrides, info, error, warning, confirm
import json
from prettytable import PrettyTable
import os
import sys
import yaml
from time import sleep
from ailib import AssistedClient
from ailib import boot_hosts as ai_boot_hosts
from ailib.common import create_onprem as ai_create_onprem
from ailib.common import delete_onprem as ai_delete_onprem

PARAMHELP = "specify parameter or keyword for rendering (multiple can be specified)"


def _list_output(_list, output):
    if output == 'yaml':
        print(yaml.dump(_list))
    elif output == 'json':
        print(json.dumps(_list, default=str))
    elif output == 'name':
        if isinstance(_list, list):
            for entry in sorted(_list, key=lambda x: x['name']):
                print(entry['name'])
        else:
            for key in sorted(list(_list.keys())):
                print(key)


def get_subparser_print_help(parser, subcommand):
    subparsers_actions = [
        action for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)]
    for subparsers_action in subparsers_actions:
        for choice, subparser in subparsers_action.choices.items():
            if choice == subcommand:
                subparser.print_help()
                return


def get_subparser(parser, subcommand):
    subparsers_actions = [
        action for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)]
    for subparsers_action in subparsers_actions:
        for choice, subparser in subparsers_action.choices.items():
            if choice == subcommand:
                return subparser


def choose_parameter_file(paramfile):
    if os.path.exists("/i_am_a_container"):
        if paramfile is not None and not os.path.isabs(paramfile):
            paramfile = f"/workdir/{paramfile}"
        elif os.path.exists("/workdir/aicli_parameters.yml"):
            paramfile = "/workdir/aicli_parameters.yml"
            info("Using default parameter file aicli_parameters.yml")
    elif paramfile is None and os.path.exists("aicli_parameters.yml"):
        paramfile = "aicli_parameters.yml"
        info("Using default parameter file aicli_parameters.yml")
    return paramfile


def create_cluster(args):
    info(f"Creating cluster {args.cluster}")
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.create_cluster(args.cluster, overrides.copy(), force=args.force)
    if overrides.get('infraenv', True):
        infraenv = f"{args.cluster}_infra-env"
        overrides['cluster'] = args.cluster
        info(f"Creating infraenv {infraenv}")
        ai.create_infra_env(infraenv, overrides)


def delete_cluster(args):
    yes = args.yes
    yes_top = args.yes_top
    if not yes and not yes_top:
        confirm("Are you sure?")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    for cluster in args.clusters:
        info(f"Deleting cluster {cluster}")
        ai.delete_cluster(cluster)
        for infra_env in ai.list_infra_envs():
            infra_env_name = infra_env.get('name')
            associated_infra_envs = [f"{cluster}_infra-env", f"{cluster}-day2_infra-env"]
            if infra_env_name is not None and infra_env_name in associated_infra_envs:
                infra_env_id = infra_env['id']
                ai.delete_infra_env(infra_env_id)


def export_cluster(args):
    info(f"Exporting cluster {args.cluster}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.export_cluster(args.cluster)


def info_cluster(args):
    if not args.full:
        skipped = ['kind', 'href', 'ssh_public_key', 'http_proxy', 'https_proxy', 'no_proxy', 'pull_secret_set',
                   'vip_dhcp_allocation', 'validations_info', 'hosts', 'image_info', 'host_networks']
    else:
        skipped = []
    fields = args.fields.split(',') if args.fields is not None else []
    values = args.values
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    if args.preflight:
        print(ai.preflight_cluster(args.cluster))
        return
    info = ai.info_cluster(args.cluster).to_dict()
    if args.output is not None:
        _list_output(info, args.output)
        return
    if fields:
        for key in list(info):
            if key not in fields:
                del info[key]
    for key in list(info):
        if key in skipped or info[key] is None:
            del info[key]
    for entry in sorted(info):
        currententry = f"{entry}: {info[entry]}" if not values else info[entry]
        print(currententry)


def info_validation(args):
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    info = ai.info_cluster(args.cluster).to_dict()
    validations = json.loads(info.get('validations_info'))
    validationstable = PrettyTable(["Id", "Type", "Status", "Message"])
    for validation in validations:
        for entry in validations[validation]:
            _id = entry['id']
            status = entry['status']
            if not args.all and status == 'success':
                continue
            message = entry['message']
            entry = [_id, validation, status, message]
            validationstable.add_row(entry)
    print(validationstable)


def list_cluster(args):
    ams_subscription_id, org_id = args.subscription, args.org
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    clusters = ai.list_clusters()
    if args.output is not None:
        _list_output(clusters, args.output)
        return
    clusterstable = PrettyTable(["Cluster", "Id", "Status", "Dns Domain"])
    for cluster in sorted(clusters, key=lambda x: x['name'] or 'zzz'):
        if ams_subscription_id is not None and cluster['ams_subscription_id'] != ams_subscription_id:
            continue
        if org_id is not None and cluster['org_id'] != org_id:
            continue
        name = cluster['name']
        status = cluster['status']
        _id = cluster['id']
        base_dns_domain = cluster.get('base_dns_domain', 'N/A')
        entry = [name, _id, status, base_dns_domain]
        clusterstable.add_row(entry)
    print(clusterstable)


def update_cluster(args):
    info(f"Updating Cluster {args.cluster}")
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.update_cluster(args.cluster, overrides)
    if overrides.get('infraenv', True):
        ai.update_infra_env(args.cluster, overrides)


def start_cluster(args):
    info(f"Starting cluster {args.cluster}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.start_cluster(args.cluster)


def stop_cluster(args):
    info(f"Stopping cluster {args.cluster}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.stop_cluster(args.cluster)


def create_deployment(args):
    info(f"Creating deployment {args.cluster}")
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.create_deployment(args.cluster, overrides, force=args.force)


def create_manifests(args):
    info(f"Uploading manifests for Cluster {args.cluster}")
    directory = args.dir
    openshift = args.openshift
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.upload_manifests(args.cluster, directory=directory, openshift=openshift)


def delete_manifests(args):
    yes = args.yes
    yes_top = args.yes_top
    if not yes and not yes_top:
        confirm("Are you sure?")
    info(f"Delete manifests from Cluster {args.cluster}")
    directory = args.dir
    manifests = args.manifests
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.delete_manifests(args.cluster, directory=directory, manifests=manifests)


def delete_host(args):
    yes = args.yes
    yes_top = args.yes_top
    if not yes and not yes_top:
        confirm("Are you sure?")
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    for hostname in args.hostnames:
        info(f"Deleting Host {hostname}")
        ai.delete_host(hostname, overrides=overrides)


def info_host(args):
    if not args.full:
        skipped = ['kind', 'logs_collected_at', 'href', 'validations_info', 'discovery_agent_version',
                   'installer_version', 'progress_stages', 'connectivity', 'ntp_sources', 'images_status',
                   'domain_name_resolutions', 'user_name', 'timestamp', 'stage_started_at', 'stage_updated_at',
                   'logs_info', 'logs_started_at']
        if not args.inventory:
            skipped.append('inventory')
    else:
        skipped = []
    fields = args.fields.split(',') if args.fields is not None else []
    values = args.values
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    hostinfo = ai.info_host(args.host)
    if hostinfo is None:
        error(f"Host {args.host} not found")
    elif args.output is not None:
        _list_output(hostinfo, args.output)
        return
    else:
        inventory = json.loads(hostinfo['inventory']) if 'inventory' in hostinfo else {}
        if fields:
            for key in list(hostinfo):
                if key not in fields:
                    del hostinfo[key]
        for key in list(hostinfo):
            if key in skipped or hostinfo[key] is None:
                del hostinfo[key]
        if inventory:
            routes = inventory.get('routes', [])
            all_addr = []
            default_nics = [x['interface'] for x in routes if x['destination'] == '0.0.0.0']
            for default_nic in default_nics:
                nic_info = next(nic for nic in inventory.get('interfaces') if nic["name"] == default_nic)
                addr = nic_info['ipv4_addresses'][0].split('/')[0]
                all_addr.append(addr)
                if 'ip' not in hostinfo:
                    hostinfo["ip"] = addr
            if len(all_addr) > 1:
                hostinfo["ips"] = all_addr

        for entry in sorted(hostinfo):
            currententry = f"{entry}: {hostinfo[entry]}" if not values else hostinfo[entry]
            print(currententry)


def list_hosts(args):
    infra_env_ids = {}
    cluster_ids = {}
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    hosts = ai.list_hosts()
    if args.output is not None:
        _list_output(hosts, args.output)
        return
    hoststable = PrettyTable(["Host", "Id", "Cluster", "Infraenv", "Status", "Role", "Ip"])
    for host in sorted(hosts, key=lambda x: x['requested_hostname'] or 'zzz'):
        name = host['requested_hostname']
        cluster_name = None
        cluster_id = host.get('cluster_id')
        if cluster_id is not None:
            if cluster_id not in cluster_ids:
                cluster_ids[cluster_id] = ai.get_cluster_name(cluster_id)
            cluster_name = cluster_ids[cluster_id]
        infra_env_id = host.get('infra_env_id')
        if infra_env_id not in infra_env_ids:
            infra_env_ids[infra_env_id] = ai.get_infra_env_name(infra_env_id)
        infra_env_name = infra_env_ids[infra_env_id]
        _id = host['id']
        role = host['role']
        if 'bootstrap' in host and host['bootstrap']:
            role += "(bootstrap)"
        status = host['status']
        inventory = json.loads(host['inventory']) if 'inventory' in host else {}
        ip = 'N/A'
        for route in inventory.get('routes', []):
            if route['destination'] == '0.0.0.0':
                default_nic = route['interface']
                nic_info = [nic for nic in inventory.get('interfaces') if nic['name'] == default_nic][0]
                ip = nic_info['ipv4_addresses'][0].split('/')[0]
        if ip == 'N/A' and 'interfaces' in inventory and inventory['interfaces']:
            if 'ipv6_addresses' in inventory['interfaces'][0] and inventory['interfaces'][0]['ipv6_addresses']:
                ip = inventory['interfaces'][0]['ipv6_addresses'][0].split('/')[0]
            if 'ipv4_addresses' in inventory['interfaces'][0] and inventory['interfaces'][0]['ipv4_addresses']:
                ip = inventory['interfaces'][0]['ipv4_addresses'][0].split('/')[0]
        entry = [name, _id, cluster_name, infra_env_name, status, role, ip]
        hoststable.add_row(entry)
    print(hoststable)


def boot_hosts(args):
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    hostnames = args.hostnames
    ai_boot_hosts(overrides, hostnames=hostnames, debug=args.debug)


def start_hosts(args):
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    hostnames = args.hostnames
    ai.start_hosts(hostnames=hostnames)


def stop_hosts(args):
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    hostnames = args.hostnames
    ai.stop_hosts(hostnames=hostnames)


def create_infra_env(args):
    info(f"Creating infraenv {args.infraenv}")
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.create_infra_env(args.infraenv, overrides)


def delete_infra_env(args):
    yes = args.yes
    yes_top = args.yes_top
    if not yes and not yes_top:
        confirm("Are you sure?")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    for infraenv in args.infraenvs:
        info(f"Deleting infraenv {infraenv}")
        ai.delete_infra_env(infraenv)


def info_infra_env(args):
    if not args.full:
        skipped = ['kind', 'href', 'ssh_public_key', 'http_proxy', 'https_proxy', 'no_proxy', 'pull_secret_set',
                   'vip_dhcp_allocation', 'validations_info', 'hosts', 'image_info', 'host_networks']
    else:
        skipped = []
    fields = args.fields.split(',') if args.fields is not None else []
    values = args.values
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    info = ai.info_infra_env(args.infraenv).to_dict()
    if fields:
        for key in list(info):
            if key not in fields:
                del info[key]
    for key in list(info):
        if key in skipped or info[key] is None:
            del info[key]
    for entry in sorted(info):
        currententry = f"{entry}: {info[entry]}" if not values else info[entry]
        print(currententry)


def list_infra_env(args):
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    infra_envs = ai.list_infra_envs()
    if args.output is not None:
        _list_output(infra_envs, args.output)
        return
    cluster_ids = {}
    infra_envs_table = PrettyTable(["Infraenv", "Id", "Cluster", "Openshift Version", "Iso Type"])
    for infra_env in sorted(infra_envs, key=lambda x: x['name'] or 'zzz'):
        name = infra_env['name']
        openshift_version = infra_env['openshift_version']
        iso_type = infra_env['type']
        _id = infra_env['id']
        cluster = None
        cluster_id = infra_env.get('cluster_id')
        if cluster_id is not None and cluster_id not in cluster_ids:
            try:
                cluster_ids[cluster_id] = ai.get_cluster_name(cluster_id)
                cluster = cluster_ids[cluster_id]
            except:
                cluster = 'N/A'
        entry = [name, _id, cluster, openshift_version, iso_type]
        infra_envs_table.add_row(entry)
    print(infra_envs_table)


def bind_infra_env(args):
    info(f"binding Infra Env {args.infraenv} to Cluster {args.cluster}")
    info("this will bind all hosts of the infraenv to given cluster")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.bind_infra_env(args.infraenv, args.cluster, force=args.force)


def start_infraenv(args):
    info(f"Starting infraenv {args.infraenv}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.start_infraenv(args.infraenv)


def stop_infraenv(args):
    info(f"Stopping infraenv {args.infraenv}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.stop_infraenv(args.infraenv)


def unbind_infra_env(args):
    info(f"Unbinding Infra Env {args.infraenv}")
    info("this will unbind all hosts of the infraenv from any cluster")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.unbind_infra_env(args.infraenv)


def update_infra_env(args):
    info(f"Updating infraenv {args.infraenv}")
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.update_infra_env(args.infraenv, overrides)


def create_iso(args):
    warning("This api call is deprecated")
    info(f"Getting Iso url for infraenv {args.infraenv}")
    paramfile = choose_parameter_file(args.paramfile)
    minimal = args.minimal
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.update_infra_env(args.infraenv, overrides)
    iso_url = ai.info_iso(args.infraenv, overrides, minimal=minimal)
    info(iso_url)


def info_iso(args):
    if not args.short:
        info(f"Getting Iso url for infraenv {args.infraenv}")
    paramfile = choose_parameter_file(args.paramfile)
    minimal = args.minimal
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    iso_url = ai.info_iso(args.infraenv, overrides, minimal=minimal)
    info(iso_url)


def download_iso(args):
    info(f"Downloading Iso for infraenv {args.infraenv} in {args.path}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.download_iso(args.infraenv, args.path)


def download_kubeadminpassword(args):
    stdout = args.stdout
    if not stdout:
        dest = f"{args.path}/kubeadmin-password.{args.cluster}"
        info(f"Downloading KubeAdminPassword for Cluster {args.cluster} in {dest}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.download_kubeadminpassword(args.cluster, args.path, stdout=stdout)


def download_kubeconfig(args):
    stdout = args.stdout
    if not stdout:
        info(f"Downloading Kubeconfig for Cluster {args.cluster} in {args.path}/kubeconfig.{args.cluster}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.download_kubeconfig(args.cluster, args.path, stdout=stdout)


def download_initrd(args):
    info(f"Downloading Initrd Config for infraenv {args.infraenv} in {args.path}/initrd.{args.infraenv}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.download_initrd(args.infraenv, args.path)


def download_installconfig(args):
    stdout = args.stdout
    if not stdout:
        info(f"Downloading Install Config for Cluster {args.cluster} in {args.path}/install-config.yaml.{args.cluster}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.download_installconfig(args.cluster, args.path, stdout=stdout)


def download_ignition(args):
    role = args.role
    info(f"Downloading {role} ignition for Cluster {args.cluster} in {args.path}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.download_ignition(args.cluster, args.path, role=role)


def download_discovery_ignition(args):
    info(f"Downloading Discovery ignition for infraenv {args.infraenv} in {args.path}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.download_discovery_ignition(args.infraenv, args.path)


def download_ipxe_script(args):
    info(f"Downloading Ipxe script for infraenv {args.infraenv} in {args.path}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    local = True if args.serve else args.local
    ai.download_ipxe_script(args.infraenv, args.path, local=local, serve=args.serve)


def download_static_networking_config(args):
    info(f"Downloading Static networking config for infraenv {args.infraenv} in {args.path}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.download_static_networking_config(args.infraenv, args.path)


def bind_host(args):
    info(f"binding Host {args.hostname} to Cluster {args.cluster}")
    overrides = {'cluster': args.cluster}
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.update_host(args.hostname, overrides)


def unbind_host(args):
    info(f"Unbinding Host {args.hostname}")
    overrides = {'cluster': None}
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.update_host(args.hostname, overrides)


def update_host(args):
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    host_param_overrides = {}
    hostnames = args.hostname
    if 'hosts' in overrides:
        host_param_overrides = overrides['hosts']
        if not hostnames:
            hostnames = [h.get('mac') or h.get('id') or h.get('name') for h in host_param_overrides if 'mac' in h or
                         'id' in h or 'name' in h]
    if not hostnames:
        warning("No hosts provided to update")
        return 1
    for hostname in hostnames:
        info(f"Updating Host {hostname}")
        host_overrides = overrides.copy()
        for entry in host_param_overrides:
            if entry.get('mac', '') == hostname or entry.get('id', '') == hostname or entry.get('name', '') == hostname:
                host_overrides.update(entry)
                break
        ai.update_host(hostname, host_overrides)


def wait_hosts(args):
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    filter_installed = args.filter
    ai.wait_hosts(args.infraenv, args.number, filter_installed=filter_installed)


def wait_cluster(args):
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.wait_cluster(args.cluster, args.status)


def list_manifests(args):
    info(f"Retrieving manifests for Cluster {args.cluster}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    manifests = ai.list_manifests(args.cluster)
    manifeststable = PrettyTable(["File", "Folder"])
    for manifest in sorted(manifests, key=lambda x: x['file_name']):
        filename = manifest['file_name']
        folder = manifest['folder']
        entry = [filename, folder]
        manifeststable.add_row(entry)
    print(manifeststable)


def update_installconfig(args):
    info(f"Updating installconfig in {args.cluster}")
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.update_installconfig(args.cluster, overrides)


def update_iso(args):
    info(f"Updating iso in {args.infraenv}")
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.update_iso(args.infraenv, overrides)


def info_service(args):
    info("Retrieving information on service")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.info_service()


def list_events(args):
    info(f"List events of cluster {args.cluster}")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    if args.follow:
        oldevents = []
        while True:
            try:
                newevents = ai.list_events(args.cluster)
                events = [event for event in newevents if event not in oldevents]
                for event in sorted(events, key=lambda x: x['event_time']):
                    print(event)
                oldevents = newevents
                sleep(10)
                ai.refresh_token(ai.token, ai.offlinetoken)
            except KeyboardInterrupt:
                info("Leaving as per your request")
                sys.exit(0)
    else:
        events = ai.list_events(args.cluster)
        if args.raw:
            for event in events:
                print(event)
        else:
            eventstable = PrettyTable(["Date", "Message"])
            for event in events:
                date = event['event_time']
                message = event['message']
                entry = [date, message]
                eventstable.add_row(entry)
            print(eventstable)


def list_infraenv_keywords(args):
    info("List infraenv keywords")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    keywords = ai.get_infraenv_keywords()
    keywordstable = PrettyTable(["Keyword"])
    for keyword in sorted(keywords):
        keywordstable.add_row([keyword])
    print(keywordstable)


def list_cluster_keywords(args):
    info("List cluster keywords")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    keywords = ai.get_cluster_keywords()
    keywordstable = PrettyTable(["Keyword"])
    for keyword in sorted(keywords):
        keywordstable.add_row([keyword])
    print(keywordstable)


def list_host_keywords(args):
    info("List host keywords")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    keywords = ai.get_host_keywords()
    keywordstable = PrettyTable(["Keyword"])
    for keyword in sorted(keywords):
        keywordstable.add_row([keyword])
    print(keywordstable)


def list_extra_keywords(args):
    info("List extra keywords")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    keywords = ai.get_extra_keywords()
    keywordstable = PrettyTable(["Keyword"])
    for keyword in sorted(keywords):
        keywordstable.add_row([keyword])
    print(keywordstable)


def create_agent_manifests(args):
    path = args.path or args.cluster
    manifests = 'ztp like agent manifests' if args.ztp else 'agent manifests'
    info(f"Creating {manifests} for {args.cluster} in path")
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken, debug=args.debug,
                        ca=args.ca, cert=args.cert, key=args.key)
    ai.create_agent_manifests(args.cluster, overrides, path=path, ztp=args.ztp)


def create_onprem(args):
    info("Creating onprem deployment")
    warning("This is not the supported path for interacting with AI")
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai_create_onprem(overrides, debug=args.debug)


def delete_onprem(args):
    info("Deleting onprem deployment")
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai_delete_onprem(overrides, debug=args.debug)


def cli():
    """

    """
    # PARAMETERS_HELP = 'specify parameter or keyword for rendering (multiple can be specified)'
    parser = argparse.ArgumentParser(description='Assisted installer assistant')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-o', '--output', choices=['json', 'name', 'yaml'], help='Format of the output')
    parser.add_argument('--staging', action='store_true', default=bool(os.environ.get('AI_STAGING', "")))
    parser.add_argument('--integration', action='store_true', default=bool(os.environ.get('AI_INTEGRATION', "")))
    parser.add_argument('-U', '--url', default=os.environ.get('AI_URL'))
    parser.add_argument('--token', default=os.environ.get('AI_TOKEN'))
    parser.add_argument('--offlinetoken', default=os.environ.get('AI_OFFLINETOKEN'))
    parser.add_argument('--ca', default=os.environ.get('AI_CA'))
    parser.add_argument('--cert', default=os.environ.get('AI_CERT'))
    parser.add_argument('--key', default=os.environ.get('AI_KEY'))
    subparsers = parser.add_subparsers(metavar='', title='Available Commands')

    bind_desc = 'Bind Object'
    bind_parser = subparsers.add_parser('bind', description=bind_desc, help=bind_desc)
    bind_subparsers = bind_parser.add_subparsers(metavar='', dest='subcommand_bind')

    hostbind_desc = 'Bind Host'
    hostbind_parser = argparse.ArgumentParser(add_help=False)
    hostbind_parser.add_argument('hostname', metavar='HOSTNAME')
    hostbind_parser.add_argument('cluster', metavar='CLUSTER')
    hostbind_parser.set_defaults(func=bind_host)
    bind_subparsers.add_parser('host', parents=[hostbind_parser], description=hostbind_desc, help=hostbind_desc)

    infraenvbind_desc = 'Bind Infraenv'
    infraenvbind_parser = argparse.ArgumentParser(add_help=False)
    infraenvbind_parser.add_argument('-f', '--force', action='store_true', help='Force')
    infraenvbind_parser.add_argument('infraenv', metavar='INFRAENV')
    infraenvbind_parser.add_argument('cluster', metavar='CLUSTER')
    infraenvbind_parser.set_defaults(func=bind_infra_env)
    bind_subparsers.add_parser('infraenv', parents=[infraenvbind_parser], description=infraenvbind_desc,
                               help=infraenvbind_desc)

    boot_desc = 'boot Object'
    boot_parser = subparsers.add_parser('boot', description=boot_desc, help=boot_desc)
    boot_subparsers = boot_parser.add_subparsers(metavar='', dest='subcommand_boot')

    hostsboot_desc = 'Boot Hosts through redfish'
    hostsboot_epilog = None
    hostsboot_parser = boot_subparsers.add_parser('host', description=hostsboot_desc,
                                                  help=hostsboot_desc, epilog=hostsboot_epilog, formatter_class=rawhelp,
                                                  aliases=['hosts'])
    hostsboot_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    hostsboot_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    hostsboot_parser.add_argument('hostnames', metavar='HOSTNAMES', nargs='*')
    hostsboot_parser.set_defaults(func=boot_hosts)

    create_desc = 'Create Object'
    create_parser = subparsers.add_parser('create', description=create_desc, help=create_desc, aliases=['add'])
    create_subparsers = create_parser.add_subparsers(metavar='', dest='subcommand_create')

    agentmanifestscreate_desc = 'Create agent based installer manifests'
    agentmanifestscreate_epilog = None
    agentmanifestscreate_parser = create_subparsers.add_parser('agent-manifests',
                                                               description=agentmanifestscreate_desc,
                                                               help=agentmanifestscreate_desc,
                                                               epilog=agentmanifestscreate_epilog,
                                                               formatter_class=rawhelp)
    agentmanifestscreate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    agentmanifestscreate_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    agentmanifestscreate_parser.add_argument('--path', metavar='PATH', help='Where to store generated assets')
    agentmanifestscreate_parser.add_argument('-z', '--ztp', action='store_true', help='Generate ZTP like manifests')
    agentmanifestscreate_parser.add_argument('cluster', metavar='CLUSTER')
    agentmanifestscreate_parser.set_defaults(func=create_agent_manifests)

    clustercreate_desc = 'Create Cluster'
    clustercreate_epilog = None
    clustercreate_parser = create_subparsers.add_parser('cluster', description=clustercreate_desc,
                                                        help=clustercreate_desc,
                                                        epilog=clustercreate_epilog, formatter_class=rawhelp)
    clustercreate_parser.add_argument('-f', '--force', action='store_true', help='Delete existing cluster if needed')
    clustercreate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    clustercreate_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    clustercreate_parser.add_argument('cluster', metavar='CLUSTER')
    clustercreate_parser.set_defaults(func=create_cluster)

    deploymentcreate_desc = 'Create Deployment e2e'
    deploymentcreate_epilog = None
    deploymentcreate_parser = create_subparsers.add_parser('deployment', description=deploymentcreate_desc,
                                                           help=deploymentcreate_desc,
                                                           epilog=deploymentcreate_epilog, formatter_class=rawhelp)
    deploymentcreate_parser.add_argument('-f', '--force', action='store_true', help='Delete existing cluster if needed')
    deploymentcreate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    deploymentcreate_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    deploymentcreate_parser.add_argument('cluster', metavar='CLUSTER')
    deploymentcreate_parser.set_defaults(func=create_deployment)

    infraenvcreate_desc = 'Create Infraenv'
    infraenvcreate_epilog = None
    infraenvcreate_parser = create_subparsers.add_parser('infraenv', description=infraenvcreate_desc,
                                                         help=infraenvcreate_desc,
                                                         epilog=infraenvcreate_epilog, formatter_class=rawhelp)
    infraenvcreate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    infraenvcreate_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    infraenvcreate_parser.add_argument('infraenv', metavar='INFRAENV')
    infraenvcreate_parser.set_defaults(func=create_infra_env)

    isocreate_desc = 'Create iso'
    isocreate_epilog = None
    isocreate_parser = create_subparsers.add_parser('iso', description=isocreate_desc, help=isocreate_desc,
                                                    epilog=isocreate_epilog, formatter_class=rawhelp)
    isocreate_parser.add_argument('-m', '--minimal', action='store_true', help='Use minimal iso')
    isocreate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    isocreate_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    isocreate_parser.add_argument('infraenv', metavar='INFRAENV')
    isocreate_parser.set_defaults(func=create_iso)

    onpremcreate_desc = 'Create Onprem Deployment'
    onpremcreate_epilog = None
    onpremcreate_parser = create_subparsers.add_parser('onprem', description=onpremcreate_desc, help=onpremcreate_desc,
                                                       epilog=onpremcreate_epilog, formatter_class=rawhelp)
    onpremcreate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    onpremcreate_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    onpremcreate_parser.set_defaults(func=create_onprem)

    manifestscreate_desc = 'Upload manifests to cluster'
    manifestscreate_epilog = None
    manifestscreate_parser = create_subparsers.add_parser('manifest', description=manifestscreate_desc,
                                                          help=manifestscreate_desc, epilog=manifestscreate_epilog,
                                                          formatter_class=rawhelp, aliases=['manifests'])
    manifestscreate_parser.add_argument('--dir', '--directory', help='directory with stored manifests', required=True)
    manifestscreate_parser.add_argument('-o', '--openshift', action='store_true', help='Store in openshift folder')
    manifestscreate_parser.add_argument('cluster', metavar='CLUSTER')
    manifestscreate_parser.set_defaults(func=create_manifests)

    delete_desc = 'Delete Object'
    delete_parser = subparsers.add_parser('delete', description=delete_desc, help=delete_desc, aliases=['remove'])
    delete_parser.add_argument('-y', '--yes', action='store_true', help='Dont ask for confirmation', dest="yes_top")
    delete_subparsers = delete_parser.add_subparsers(metavar='', dest='subcommand_delete')

    clusterdelete_desc = 'Delete Cluster'
    clusterdelete_epilog = None
    clusterdelete_parser = delete_subparsers.add_parser('cluster', description=clusterdelete_desc,
                                                        help=clusterdelete_desc,
                                                        epilog=clusterdelete_epilog, formatter_class=rawhelp,
                                                        aliases=['deployment'])
    clusterdelete_parser.add_argument('-y', '--yes', action='store_true', help='Dont ask for confirmation')
    clusterdelete_parser.add_argument('clusters', metavar='CLUSTERS', nargs='*')
    clusterdelete_parser.set_defaults(func=delete_cluster)

    infraenvdelete_desc = 'Delete Infraenv'
    infraenvdelete_epilog = None
    infraenvdelete_parser = delete_subparsers.add_parser('infraenv', description=infraenvdelete_desc,
                                                         help=infraenvdelete_desc,
                                                         epilog=infraenvdelete_epilog, formatter_class=rawhelp)
    infraenvdelete_parser.add_argument('-y', '--yes', action='store_true', help='Dont ask for confirmation')
    infraenvdelete_parser.add_argument('infraenvs', metavar='INFRAENVS', nargs='*')
    infraenvdelete_parser.set_defaults(func=delete_infra_env)

    hostdelete_desc = 'Delete host'
    hostdelete_parser = argparse.ArgumentParser(add_help=False)
    hostdelete_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    hostdelete_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    hostdelete_parser.add_argument('-y', '--yes', action='store_true', help='Dont ask for confirmation')
    hostdelete_parser.add_argument('hostnames', metavar='HOSTNAMES', nargs='*')
    hostdelete_parser.set_defaults(func=delete_host)
    delete_subparsers.add_parser('host', parents=[hostdelete_parser], description=hostdelete_desc, help=hostdelete_desc)

    manifestsdelete_desc = 'Delete manifests to cluster'
    manifestsdelete_epilog = None
    manifestsdelete_parser = delete_subparsers.add_parser('manifest', description=manifestsdelete_desc,
                                                          help=manifestsdelete_desc, epilog=manifestsdelete_epilog,
                                                          formatter_class=rawhelp, aliases=['manifests'])
    manifestsdelete_parser.add_argument('--dir', '--directory', help='directory with stored manifests')
    manifestsdelete_parser.add_argument('-y', '--yes', action='store_true', help='Dont ask for confirmation')
    manifestsdelete_parser.add_argument('cluster', metavar='CLUSTER')
    manifestsdelete_parser.add_argument('manifests', metavar='MANIFESTS', nargs='*')
    manifestsdelete_parser.set_defaults(func=delete_manifests)

    onpremdelete_desc = 'Delete Onprem'
    onpremdelete_epilog = None
    onpremdelete_parser = delete_subparsers.add_parser('onprem', description=onpremdelete_desc,
                                                       help=onpremdelete_desc,
                                                       epilog=onpremdelete_epilog, formatter_class=rawhelp)
    onpremdelete_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    onpremdelete_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    onpremdelete_parser.add_argument('-y', '--yes', action='store_true', help='Dont ask for confirmation')
    onpremdelete_parser.set_defaults(func=delete_onprem)

    download_desc = 'Download Assets'
    download_parser = subparsers.add_parser('download', description=download_desc, help=download_desc)
    download_subparsers = download_parser.add_subparsers(metavar='', dest='subcommand_download')

    ignitiondiscoverydownload_desc = 'Download Discovery Ignition file'
    ignitiondiscoverydownload_parser = argparse.ArgumentParser(add_help=False)
    ignitiondiscoverydownload_parser.add_argument('-p', '--path', metavar='PATH', default='.',
                                                  help='Where to download asset')
    ignitiondiscoverydownload_parser.add_argument('infraenv', metavar='INFRAENV')
    ignitiondiscoverydownload_parser.set_defaults(func=download_discovery_ignition)
    download_subparsers.add_parser('discovery-ignition', parents=[ignitiondiscoverydownload_parser],
                                   description=ignitiondiscoverydownload_desc,
                                   help=ignitiondiscoverydownload_desc)

    ignitiondownload_desc = 'Download Ignition file'
    ignitiondownload_parser = argparse.ArgumentParser(add_help=False)
    ignitiondownload_parser.add_argument('-p', '--path', metavar='PATH', default='.', help='Where to download asset')
    ignitiondownload_parser.add_argument('-r', '--role', metavar='ROLE', default='worker',
                                         help='Which role to download')
    ignitiondownload_parser.add_argument('cluster', metavar='CLUSTER')
    ignitiondownload_parser.set_defaults(func=download_ignition)
    download_subparsers.add_parser('ignition', parents=[ignitiondownload_parser],
                                   description=ignitiondownload_desc,
                                   help=ignitiondownload_desc)

    ipxescriptdownload_desc = 'Download Discovery Ipxe script'
    ipxescriptdownload_parser = argparse.ArgumentParser(add_help=False)
    ipxescriptdownload_parser.add_argument('-l', '--local', action='store_true', help='Convert artifacts for local use')
    ipxescriptdownload_parser.add_argument('-p', '--path', metavar='PATH', default='.', help='Where to download asset')
    ipxescriptdownload_parser.add_argument('-s', '--serve', action='store_true', help='Serve downloaded assets')
    ipxescriptdownload_parser.add_argument('infraenv', metavar='INFRAENV')
    ipxescriptdownload_parser.set_defaults(func=download_ipxe_script)
    download_subparsers.add_parser('ipxe-script', parents=[ipxescriptdownload_parser],
                                   description=ipxescriptdownload_desc,
                                   help=ipxescriptdownload_desc)

    initrddownload_desc = 'Download Initrd'
    initrddownload_parser = argparse.ArgumentParser(add_help=False)
    initrddownload_parser.add_argument('--path', metavar='PATH', default='.', help='Where to download asset')
    initrddownload_parser.add_argument('infraenv', metavar='INFRAENV')
    initrddownload_parser.set_defaults(func=download_initrd)
    download_subparsers.add_parser('initrd', parents=[initrddownload_parser], description=initrddownload_desc,
                                   help=initrddownload_desc)

    installconfigdownload_desc = 'Download Installconfig'
    installconfigdownload_parser = argparse.ArgumentParser(add_help=False)
    installconfigdownload_parser.add_argument('--path', metavar='PATH', default='.', help='Where to download asset')
    installconfigdownload_parser.add_argument('-s', '--stdout', action='store_true', help='Print to stdout')
    installconfigdownload_parser.add_argument('cluster', metavar='CLUSTER')
    installconfigdownload_parser.set_defaults(func=download_installconfig)
    download_subparsers.add_parser('installconfig', parents=[installconfigdownload_parser],
                                   description=installconfigdownload_desc,
                                   help=installconfigdownload_desc)

    infraenv_help = "The infraenv associated to the cluster. Cluster name can also be used"
    isodownload_desc = 'Download Iso'
    isodownload_parser = argparse.ArgumentParser(add_help=False)
    isodownload_parser.add_argument('-p', '--path', metavar='PATH', default='.', help='Where to download asset')
    isodownload_parser.add_argument('infraenv', metavar='INFRAENV', help=infraenv_help)
    isodownload_parser.set_defaults(func=download_iso)
    download_subparsers.add_parser('iso', parents=[isodownload_parser],
                                   description=isodownload_desc,
                                   help=isodownload_desc)

    kubepassworddownload_desc = 'Download Kubeadmin-password'
    kubepassworddownload_parser = argparse.ArgumentParser(add_help=False)
    kubepassworddownload_parser.add_argument('--path', metavar='PATH', default='.', help='Where to download asset')
    kubepassworddownload_parser.add_argument('-s', '--stdout', action='store_true', help='Print to stdout')
    kubepassworddownload_parser.add_argument('cluster', metavar='CLUSTER')
    kubepassworddownload_parser.set_defaults(func=download_kubeadminpassword)
    download_subparsers.add_parser('kubeadmin-password', parents=[kubepassworddownload_parser],
                                   description=kubepassworddownload_desc,
                                   help=kubepassworddownload_desc)

    kubeconfigdownload_desc = 'Download Kubeconfig'
    kubeconfigdownload_parser = argparse.ArgumentParser(add_help=False)
    kubeconfigdownload_parser.add_argument('--path', metavar='PATH', default='.', help='Where to download asset')
    kubeconfigdownload_parser.add_argument('-s', '--stdout', action='store_true', help='Print to stdout')
    kubeconfigdownload_parser.add_argument('cluster', metavar='CLUSTER')
    kubeconfigdownload_parser.set_defaults(func=download_kubeconfig)
    download_subparsers.add_parser('kubeconfig', parents=[kubeconfigdownload_parser],
                                   description=kubeconfigdownload_desc,
                                   help=kubeconfigdownload_desc)

    staticnetworkingdownload_desc = 'Download Static network config'
    staticnetworkingdownload_parser = argparse.ArgumentParser(add_help=False)
    staticnetworkingdownload_parser.add_argument('-p', '--path', metavar='PATH', default='.',
                                                 help='Where to download asset')
    staticnetworkingdownload_parser.add_argument('infraenv', metavar='INFRAENV')
    staticnetworkingdownload_parser.set_defaults(func=download_static_networking_config)
    download_subparsers.add_parser('static-network-config', parents=[staticnetworkingdownload_parser],
                                   description=staticnetworkingdownload_desc,
                                   help=staticnetworkingdownload_desc)

    export_desc = 'Export Object'
    export_parser = subparsers.add_parser('export', description=export_desc, help=export_desc)
    export_subparsers = export_parser.add_subparsers(metavar='', dest='subcommand_export')

    clusterexport_desc = 'Export Clusters'
    clusterexport_parser = argparse.ArgumentParser(add_help=False)
    clusterexport_parser.add_argument('cluster', metavar='CLUSTER')
    clusterexport_parser.set_defaults(func=export_cluster)
    export_subparsers.add_parser('cluster', parents=[clusterexport_parser], description=clusterexport_desc,
                                 help=clusterexport_desc, aliases=['clusters'])

    info_desc = 'Info Object'
    info_parser = subparsers.add_parser('info', description=info_desc, help=info_desc)
    info_subparsers = info_parser.add_subparsers(metavar='', dest='subcommand_info')

    clusterinfo_desc = 'Info Cluster'
    clusterinfo_epilog = None
    clusterinfo_parser = info_subparsers.add_parser('cluster', description=clusterinfo_desc, help=clusterinfo_desc,
                                                    epilog=clusterinfo_epilog, formatter_class=rawhelp)
    clusterinfo_parser.add_argument('-f', '--fields', help='Display Corresponding list of fields,'
                                    'separated by a comma', metavar='FIELDS')
    clusterinfo_parser.add_argument('-v', '--values', action='store_true', help='Only report values')
    clusterinfo_parser.add_argument('--full', action='store_true', help='Full output')
    clusterinfo_parser.add_argument('-p', '--preflight', action='store_true', help='Show preflight')
    clusterinfo_parser.add_argument('cluster', metavar='CLUSTER')
    clusterinfo_parser.set_defaults(func=info_cluster)

    validationinfo_desc = 'Info validation'
    validationinfo_epilog = None
    validationinfo_parser = info_subparsers.add_parser('validation', description=validationinfo_desc,
                                                       help=validationinfo_desc, epilog=validationinfo_epilog,
                                                       formatter_class=rawhelp, aliases=['validations'])
    validationinfo_parser.add_argument('-a', '--all', action='store_true', help='Report successful checks too')
    validationinfo_parser.add_argument('cluster', metavar='CLUSTER')
    validationinfo_parser.set_defaults(func=info_validation)

    infraenvinfo_desc = 'Info Infraenv'
    infraenvinfo_epilog = None
    infraenvinfo_parser = info_subparsers.add_parser('infraenv', description=infraenvinfo_desc, help=infraenvinfo_desc,
                                                     epilog=infraenvinfo_epilog, formatter_class=rawhelp)
    infraenvinfo_parser.add_argument('-f', '--fields', help='Display Corresponding list of fields,'
                                     'separated by a comma', metavar='FIELDS')
    infraenvinfo_parser.add_argument('-v', '--values', action='store_true', help='Only report values')
    infraenvinfo_parser.add_argument('--full', action='store_true', help='Full output')
    infraenvinfo_parser.add_argument('infraenv', metavar='INFRAENV')
    infraenvinfo_parser.set_defaults(func=info_infra_env)

    isoinfo_desc = 'Get iso url'
    isoinfo_epilog = None
    isoinfo_parser = info_subparsers.add_parser('iso', description=isoinfo_desc, help=isoinfo_desc,
                                                epilog=isoinfo_epilog, formatter_class=rawhelp)
    isoinfo_parser.add_argument('-m', '--minimal', action='store_true', help='Use minimal iso')
    isoinfo_parser.add_argument('-s', '--short', action='store_true', help='Only print iso url')
    isoinfo_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    isoinfo_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    isoinfo_parser.add_argument('infraenv', metavar='INFRAENV')
    isoinfo_parser.set_defaults(func=info_iso)

    hostinfo_desc = 'Info Host'
    hostinfo_epilog = None
    hostinfo_parser = info_subparsers.add_parser('host', description=hostinfo_desc, help=hostinfo_desc,
                                                 epilog=hostinfo_epilog, formatter_class=rawhelp)
    hostinfo_parser.add_argument('-i', '--inventory', action='store_true', help='Report host inventory')
    hostinfo_parser.add_argument('-f', '--fields', help='Display Corresponding list of fields,'
                                 'separated by a comma', metavar='FIELDS')
    hostinfo_parser.add_argument('-v', '--values', action='store_true', help='Only report values')
    hostinfo_parser.add_argument('--full', action='store_true', help='Full output')
    hostinfo_parser.add_argument('host', metavar='HOST')
    hostinfo_parser.set_defaults(func=info_host)

    serviceinfo_desc = 'Info Service'
    serviceinfo_epilog = None
    serviceinfo_parser = info_subparsers.add_parser('service', description=serviceinfo_desc, help=serviceinfo_desc,
                                                    epilog=serviceinfo_epilog, formatter_class=rawhelp)
    serviceinfo_parser.set_defaults(func=info_service)

    list_desc = 'List Object'
    list_parser = subparsers.add_parser('list', description=list_desc, help=list_desc, aliases=['get'])
    list_subparsers = list_parser.add_subparsers(metavar='', dest='subcommand_list')

    clusterlist_desc = 'List Clusters'
    clusterlist_parser = argparse.ArgumentParser(add_help=False)
    clusterlist_parser.add_argument('-s', '--subscription', help='Filter by specified ams_subscription_id',
                                    metavar='SUBSCRIPTION')
    clusterlist_parser.add_argument('-o', '--org', help='Filter by specified org_id', metavar='ORG')
    clusterlist_parser.set_defaults(func=list_cluster)
    list_subparsers.add_parser('cluster', parents=[clusterlist_parser], description=clusterlist_desc,
                               help=clusterlist_desc, aliases=['clusters'])

    cluster_keywords_list_desc = 'List Cluster keywords'
    cluster_keywords_list_parser = argparse.ArgumentParser(add_help=False)
    cluster_keywords_list_parser.set_defaults(func=list_cluster_keywords)
    list_subparsers.add_parser('cluster-keyword', parents=[cluster_keywords_list_parser],
                               description=cluster_keywords_list_desc,
                               help=cluster_keywords_list_desc, aliases=['cluster-keywords'])

    eventslist_desc = 'List Events'
    eventslist_parser = argparse.ArgumentParser(add_help=False)
    eventslist_parser.add_argument('-f', '--follow', action='store_true')
    eventslist_parser.add_argument('-r', '--raw', action='store_true')
    eventslist_parser.add_argument('cluster', metavar='CLUSTER')
    eventslist_parser.set_defaults(func=list_events)
    list_subparsers.add_parser('event', parents=[eventslist_parser], description=eventslist_desc,
                               help=eventslist_desc, aliases=['events'])

    extra_keywords_list_desc = 'List Extra keywords'
    extra_keywords_list_parser = argparse.ArgumentParser(add_help=False)
    extra_keywords_list_parser.set_defaults(func=list_extra_keywords)
    list_subparsers.add_parser('extra-keyword', parents=[extra_keywords_list_parser],
                               description=extra_keywords_list_desc,
                               help=extra_keywords_list_desc, aliases=['extra-keywords'])

    hostslist_desc = 'List Hosts'
    hostslist_parser = argparse.ArgumentParser(add_help=False)
    hostslist_parser.set_defaults(func=list_hosts)
    list_subparsers.add_parser('host', parents=[hostslist_parser], description=hostslist_desc,
                               help=hostslist_desc, aliases=['hosts'])

    host_keywords_list_desc = 'List Host keywords'
    host_keywords_list_parser = argparse.ArgumentParser(add_help=False)
    host_keywords_list_parser.set_defaults(func=list_host_keywords)
    list_subparsers.add_parser('host-keyword', parents=[host_keywords_list_parser],
                               description=host_keywords_list_desc,
                               help=host_keywords_list_desc, aliases=['host-keywords'])

    infraenvlist_desc = 'List Infraenvs'
    infraenvlist_parser = argparse.ArgumentParser(add_help=False)
    infraenvlist_parser.set_defaults(func=list_infra_env)
    list_subparsers.add_parser('infraenv', parents=[infraenvlist_parser], description=infraenvlist_desc,
                               help=infraenvlist_desc, aliases=['infraenvs'])

    infraenv_keywords_list_desc = 'List Infraenv keywords'
    infraenv_keywords_list_parser = argparse.ArgumentParser(add_help=False)
    infraenv_keywords_list_parser.set_defaults(func=list_infraenv_keywords)
    list_subparsers.add_parser('infraenv-keyword', parents=[infraenv_keywords_list_parser],
                               description=infraenv_keywords_list_desc,
                               help=infraenv_keywords_list_desc, aliases=['infraenv-keywords'])

    manifestslist_desc = 'List Manifests of a cluster'
    manifestslist_parser = argparse.ArgumentParser(add_help=False)
    manifestslist_parser.add_argument('cluster', metavar='CLUSTER')
    manifestslist_parser.set_defaults(func=list_manifests)
    list_subparsers.add_parser('manifest', parents=[manifestslist_parser], description=manifestslist_desc,
                               help=manifestslist_desc, aliases=['manifests'])

    start_desc = 'Start Object'
    start_parser = subparsers.add_parser('start', description=start_desc, help=start_desc, aliases=['launch'])
    start_subparsers = start_parser.add_subparsers(metavar='', dest='subcommand_start')

    clusterstart_desc = 'Start Cluster'
    clusterstart_epilog = None
    clusterstart_parser = start_subparsers.add_parser('cluster', description=clusterstart_desc,
                                                      help=clusterstart_desc,
                                                      epilog=clusterstart_epilog, formatter_class=rawhelp)
    clusterstart_parser.add_argument('cluster', metavar='CLUSTER')
    clusterstart_parser.set_defaults(func=start_cluster)

    hostsstart_desc = 'Start (day2) Hosts'
    hostsstart_epilog = None
    hostsstart_parser = start_subparsers.add_parser('host', description=hostsstart_desc,
                                                    help=hostsstart_desc,
                                                    epilog=hostsstart_epilog, formatter_class=rawhelp,
                                                    aliases=['hosts'])
    hostsstart_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    hostsstart_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    hostsstart_parser.add_argument('hostnames', metavar='HOSTNAMES', nargs='*')
    hostsstart_parser.set_defaults(func=start_hosts)

    infraenvstart_desc = 'Start Infraenv'
    infraenvstart_epilog = None
    infraenvstart_parser = start_subparsers.add_parser('infraenv', description=infraenvstart_desc,
                                                       help=infraenvstart_desc,
                                                       epilog=infraenvstart_epilog, formatter_class=rawhelp)
    infraenvstart_parser.add_argument('infraenv', metavar='INFRAENV')
    infraenvstart_parser.set_defaults(func=start_infraenv)

    stop_desc = 'Stop Object'
    stop_parser = subparsers.add_parser('stop', description=stop_desc, help=stop_desc, aliases=['reset'])
    stop_subparsers = stop_parser.add_subparsers(metavar='', dest='subcommand_stop')

    clusterstop_desc = 'Stop Cluster'
    clusterstop_epilog = None
    clusterstop_parser = stop_subparsers.add_parser('cluster', description=clusterstop_desc,
                                                    help=clusterstop_desc,
                                                    epilog=clusterstop_epilog, formatter_class=rawhelp)
    clusterstop_parser.add_argument('cluster', metavar='CLUSTER')
    clusterstop_parser.set_defaults(func=stop_cluster)

    hostsstop_desc = 'Stop (day2) Hosts'
    hostsstop_epilog = None
    hostsstop_parser = stop_subparsers.add_parser('host', description=hostsstop_desc, help=hostsstop_desc,
                                                  epilog=hostsstop_epilog, formatter_class=rawhelp,
                                                  aliases=['hosts'])
    hostsstop_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    hostsstop_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    hostsstop_parser.add_argument('hostnames', metavar='HOSTNAMES', nargs='*')
    hostsstop_parser.set_defaults(func=stop_hosts)

    infraenvstop_desc = 'Stop Infraenv'
    infraenvstop_epilog = None
    infraenvstop_parser = stop_subparsers.add_parser('infraenv', description=infraenvstop_desc, help=infraenvstop_desc,
                                                     epilog=infraenvstop_epilog, formatter_class=rawhelp)
    infraenvstop_parser.add_argument('infraenv', metavar='INFRAENV')
    infraenvstop_parser.set_defaults(func=stop_infraenv)

    unbind_desc = 'Unbind Object'
    unbind_parser = subparsers.add_parser('unbind', description=unbind_desc, help=unbind_desc)
    unbind_subparsers = unbind_parser.add_subparsers(metavar='', dest='subcommand_unbind')

    hostunbind_desc = 'Unbind Host'
    hostunbind_parser = argparse.ArgumentParser(add_help=False)
    hostunbind_parser.add_argument('hostname', metavar='HOSTNAME')
    hostunbind_parser.set_defaults(func=unbind_host)
    unbind_subparsers.add_parser('host', parents=[hostunbind_parser], description=hostunbind_desc, help=hostunbind_desc)

    infraenvunbind_desc = 'Unbind Infra Env'
    infraenvunbind_parser = argparse.ArgumentParser(add_help=False)
    infraenvunbind_parser.add_argument('infraenv', metavar='INFRAENV')
    infraenvunbind_parser.set_defaults(func=unbind_infra_env)
    unbind_subparsers.add_parser('infraenv', parents=[infraenvunbind_parser],
                                 description=infraenvunbind_desc, help=infraenvunbind_desc)

    update_desc = 'Update Object'
    update_parser = subparsers.add_parser('update', description=update_desc, help=update_desc, aliases=['patch'])
    update_subparsers = update_parser.add_subparsers(metavar='', dest='subcommand_update')

    clusterupdate_desc = 'Update Cluster'
    clusterupdate_parser = argparse.ArgumentParser(add_help=False)
    clusterupdate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    clusterupdate_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    clusterupdate_parser.add_argument('cluster', metavar='CLUSTER')
    clusterupdate_parser.set_defaults(func=update_cluster)
    update_subparsers.add_parser('cluster', parents=[clusterupdate_parser], description=clusterupdate_desc,
                                 help=clusterupdate_desc)

    hostupdate_desc = 'Update Host name and role'
    hostupdate_parser = argparse.ArgumentParser(add_help=False)
    hostupdate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    hostupdate_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    hostupdate_parser.add_argument('hostname', metavar='HOSTNAME', nargs='*')
    hostupdate_parser.set_defaults(func=update_host)
    update_subparsers.add_parser('host', parents=[hostupdate_parser], description=hostupdate_desc, help=hostupdate_desc,
                                 aliases=['hosts'])

    infraenvupdate_desc = 'Update Infraenv'
    infraenvupdate_parser = argparse.ArgumentParser(add_help=False)
    infraenvupdate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    infraenvupdate_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    infraenvupdate_parser.add_argument('infraenv', metavar='INFRAENV')
    infraenvupdate_parser.set_defaults(func=update_infra_env)
    update_subparsers.add_parser('infraenv', parents=[infraenvupdate_parser], description=infraenvupdate_desc,
                                 help=infraenvupdate_desc)

    installconfigpatch_desc = 'Update Installconfig'
    installconfigpatch_parser = argparse.ArgumentParser(add_help=False)
    installconfigpatch_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    installconfigpatch_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    installconfigpatch_parser.add_argument('cluster', metavar='CLUSTER')
    installconfigpatch_parser.set_defaults(func=update_installconfig)
    update_subparsers.add_parser('installconfig', parents=[installconfigpatch_parser],
                                 description=installconfigpatch_desc, help=installconfigpatch_desc)

    isopatch_desc = 'Update Discovery Iso'
    isopatch_parser = argparse.ArgumentParser(add_help=False)
    isopatch_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    isopatch_parser.add_argument('--paramfile', '--pf', help='Parameters file', metavar='PARAMFILE')
    isopatch_parser.add_argument('infraenv', metavar='INFRAENV')
    isopatch_parser.set_defaults(func=update_iso)
    update_subparsers.add_parser('iso', parents=[isopatch_parser], description=isopatch_desc, help=isopatch_desc)

    wait_desc = 'Wait Object'
    wait_parser = subparsers.add_parser('wait', description=wait_desc, help=wait_desc)
    wait_subparsers = wait_parser.add_subparsers(metavar='', dest='subcommand_wait')

    clusterwait_desc = 'Wait for cluster'
    clusterwait_parser = argparse.ArgumentParser(add_help=False)
    clusterwait_parser.add_argument('-s', '--status', help='Which status to wait for', choices=('installed', 'ready'),
                                    default='installed')
    clusterwait_parser.add_argument('cluster', metavar='CLUSTER')
    clusterwait_parser.set_defaults(func=wait_cluster)
    wait_subparsers.add_parser('cluster', parents=[clusterwait_parser], description=clusterwait_desc,
                               help=clusterwait_desc)

    hostswait_desc = 'Wait for hosts'
    hostswait_parser = argparse.ArgumentParser(add_help=False)
    hostswait_parser.add_argument('-f', '--filter', action='store_true', help='Filter installed hosts')
    hostswait_parser.add_argument('-n', '--number', help='Number of nodes to wait for. Default to 3', type=int,
                                  default=3)
    hostswait_parser.add_argument('infraenv', metavar='INFRAENV')
    hostswait_parser.set_defaults(func=wait_hosts)
    wait_subparsers.add_parser('host', parents=[hostswait_parser], description=hostswait_desc, help=hostswait_desc,
                               aliases=['hosts'])

    if len(sys.argv) == 1:
        parser.print_help()
        os._exit(0)
    args = parser.parse_args()
    if not hasattr(args, 'func'):
        for attr in dir(args):
            if attr.startswith('subcommand_') and getattr(args, attr) is None:
                split = attr.split('_')
                if len(split) == 2:
                    subcommand = split[1]
                    get_subparser_print_help(parser, subcommand)
                elif len(split) == 3:
                    subcommand = split[1]
                    subsubcommand = split[2]
                    subparser = get_subparser(parser, subcommand)
                    get_subparser_print_help(subparser, subsubcommand)
                os._exit(0)
        os._exit(0)
    if args.url is None:
        if args.staging:
            args.url = "https://api.stage.openshift.com"
        elif args.integration:
            args.url = "https://api.integration.openshift.com"
        else:
            args.url = "https://api.openshift.com"
    args.func(args)


if __name__ == '__main__':
    cli()
