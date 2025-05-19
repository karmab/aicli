import json
import os
import re
import yaml
from ailib import AssistedClient
from ailib import boot_hosts as ai_boot_hosts
from ailib.common import create_onprem as ai_create_onprem
from ailib.common import delete_onprem as ai_delete_onprem
from mcp.server.fastmcp import FastMCP
from urllib.request import urlopen

mcp = FastMCP("aiclimcp")


@mcp.prompt()
def prompt() -> str:
    """Indicates contexts of questions related to aicli"""
    return """You are a helpful assistant who knows everything about aicli, a python client
    on top of the generated assisted-installer python library to ease working with assisted installer API"""


@mcp.resource("resource://aicli-doc.md")
def get_doc() -> str:
    """Provides aicli documentation"""
    url = 'https://raw.githubusercontent.com/karmab/aicli/refs/heads/main/docs/index.md'
    return urlopen(url).read().decode('utf-8')


@mcp.tool()
def create_cluster(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                   offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                   key: str = None, force: bool = False, overrides: dict = {}) -> dict:
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.create_cluster(cluster, overrides.copy(), force=force)
    if overrides.get('infraenv', True):
        infraenv = f"{cluster}_infra-env"
        overrides['cluster'] = cluster
        ai.create_infra_env(infraenv, overrides, quiet=True)


@mcp.tool()
def delete_cluster(clusters: list, allclusters: bool = False, url: str = "https://api.openshift.com", token: str = None,
                   offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                   key: str = None) -> dict:
    """ Delete cluster """
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    clusters = [clu['name'] for clu in ai.list_clusters()] if allclusters else clusters
    for cluster in clusters:
        ai.delete_cluster(cluster)
        for infra_env in ai.list_infra_envs():
            infra_env_name = infra_env.get('name')
            associated_infra_envs = [f"{cluster}_infra-env", f"{cluster}-day2_infra-env"]
            if infra_env_name is not None and infra_env_name in associated_infra_envs:
                infra_env_id = infra_env['id']
                ai.delete_infra_env(infra_env_id)


@mcp.tool()
def export_cluster(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                   offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                   key: str = None):
    """Export cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    return ai.export_cluster(cluster)


@mcp.tool()
def info_cluster(cluster: str, full: bool = False, fields: list = [], preflight: bool = False,
                 url: str = "https://api.openshift.com", token: str = None, offlinetoken: str = None,
                 debug: bool = False, ca: str = None, cert: str = None,
                 key: str = None) -> dict:
    """Provide information on cluster"""
    if not full:
        skipped = ['kind', 'href', 'ssh_public_key', 'http_proxy', 'https_proxy', 'no_proxy', 'pull_secret_set',
                   'vip_dhcp_allocation', 'validations_info', 'hosts', 'image_info', 'host_networks']
    else:
        skipped = []
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    if preflight:
        print(ai.preflight_cluster(cluster))
        return
    info = ai.info_cluster(cluster).to_dict()
    if fields:
        for key in list(info):
            if key not in fields:
                del info[key]
    for key in list(info):
        if key in skipped or info[key] is None:
            del info[key]
    return info


@mcp.tool()
def info_validation(cluster: str, allmessages: bool = False, url: str = "https://api.openshift.com", token: str = None,
                    offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                    key: str = None) -> list:
    """Get validations on cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    info = ai.info_cluster(cluster).to_dict()
    validations = json.loads(info.get('validations_info'))
    validationstable = ["Id", "Type", "Status", "Message"]
    for validation in validations:
        for entry in validations[validation]:
            _id = entry['id']
            status = entry['status']
            if not allmessages and status == 'success':
                continue
            message = entry['message']
            entry = [_id, validation, status, message]
            validationstable.append(entry)
    return validationstable


@mcp.tool()
def list_clusters(subscription: str = None, org: str = None, url: str = "https://api.openshift.com", token: str = None,
                  offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                  key: str = None) -> list:
    """List aicli clusters"""
    ams_subscription_id, org_id = subscription, org
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    clusters = ai.list_clusters()
    clusterstable = ["Cluster", "Id", "Status", "Dns Domain"]
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
        clusterstable.append(entry)
    return clusterstable


@mcp.tool()
def update_cluster(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                   offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                   key: str = None, overrides: dict = {}):
    """Update cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.update_cluster(cluster, overrides)
    if overrides.get('infraenv', True):
        ai.update_infra_env(cluster, overrides)


@mcp.tool()
def start_cluster(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                  offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                  key: str = None):
    """Start cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.start_cluster(cluster)


@mcp.tool()
def stop_cluster(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                 offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                 key: str = None):
    """Stop cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.stop_cluster(cluster)


@mcp.tool()
def create_deployment(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                      offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                      key: str = None, force: bool = False, debugredfish: bool = False, overrides: dict = {}):
    """Create deployment of cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.create_deployment(cluster, overrides, force=force, debug=debugredfish)


@mcp.tool()
def scale_deployment(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                     offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                     key: str = None, debugredfish: bool = False, overrides: dict = {}):
    """"Scale deployment of cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.scale_deployment(cluster, overrides, debug=debugredfish)


@mcp.tool()
def create_manifests(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                     offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                     key: str = None, directory: str = '.', openshift: bool = False):
    """Upload manifests of cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.upload_manifests(cluster, directory=directory, openshift=openshift)


@mcp.tool()
def delete_manifests(cluster: str, manifests: list = [], url: str = "https://api.openshift.com", token: str = None,
                     offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                     key: str = None, directory: str = '.'):
    """Delete manifests of cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.delete_manifests(cluster, directory=directory, manifests=manifests)


@mcp.tool()
def delete_host(hostname: str, url: str = "https://api.openshift.com", token: str = None,
                offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                key: str = None, overrides: dict = {}):
    """Delete host"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.delete_host(hostname, overrides=overrides)


@mcp.tool()
def info_host(host: str, url: str = "https://api.openshift.com", token: str = None,
              offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
              key: str = None, full: bool = False, inventory: bool = False, fields: list = []) -> dict:
    """Provide information on host"""
    if not full:
        skipped = ['kind', 'logs_collected_at', 'href', 'validations_info', 'discovery_agent_version',
                   'installer_version', 'progress_stages', 'connectivity', 'ntp_sources', 'images_status',
                   'domain_name_resolutions', 'user_name', 'timestamp', 'stage_started_at', 'stage_updated_at',
                   'logs_info', 'logs_started_at']
        if not inventory:
            skipped.append('inventory')
    else:
        skipped = []
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    hostinfo = ai.info_host(host)
    if hostinfo is None:
        return {'result': 'failure', 'reason': f"Host {host} not found"}
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
        return hostinfo


@mcp.tool()
def list_hosts(url: str = "https://api.openshift.com", token: str = None,
               offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
               key: str = None) -> list:
    """List hosts"""
    infra_env_ids = {}
    cluster_ids = {}
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    hosts = ai.list_hosts()
    hoststable = ["Host", "Id", "Cluster", "Infraenv", "Status", "Role", "Ip"]
    for host in sorted(hosts, key=lambda x: x['requested_hostname'] or 'zzz'):
        name = host['requested_hostname']
        cluster_name = None
        cluster_id = host.get('cluster_id')
        if cluster_id is not None:
            if cluster_id not in cluster_ids:
                try:
                    cluster_ids[cluster_id] = ai.get_cluster_name(cluster_id)
                    cluster_name = cluster_ids[cluster_id]
                except:
                    cluster_name = cluster_id
        else:
            cluster_name = 'N/A'
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
        hoststable.append(entry)
    return hoststable


@mcp.tool()
def boot_hosts(hostnames: list, url: str = "https://api.openshift.com", token: str = None,
               offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
               key: str = None, overrides: dict = {}):
    """Boot hosts"""
    ai_boot_hosts(overrides, hostnames=hostnames, debug=debug)


@mcp.tool()
def start_hosts(hostnames: list, url: str = "https://api.openshift.com", token: str = None,
                offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                key: str = None):
    """Start hosts"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.start_hosts(hostnames=hostnames)


@mcp.tool()
def stop_hosts(hostnames: list, url: str = "https://api.openshift.com", token: str = None,
               offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
               key: str = None):
    """Stop hosts"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.stop_hosts(hostnames=hostnames)


@mcp.tool()
def create_fake_hosts(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                      offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                      key: str = None, overrides: dict = {}, count: int = 3):
    """Create fake hosts"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    if 'pull_secret' not in overrides:
        overrides['pull_secret'] = "openshift_pull.json"
    pull_secret = os.path.expanduser(overrides['pull_secret'])
    if os.path.exists(pull_secret):
        pull_secret = re.sub(r"\s", "", open(pull_secret).read())
    elif '{' not in pull_secret:
        return "Couldn't parse pull secret file {pull_secret}"
    pull_secret_data = json.loads(pull_secret)
    secret_key = pull_secret_data['auths']['cloud.openshift.com']['auth']
    for num in range(0, count):
        hostname = f"{cluster}-node-{num}"
        ai.create_fake_host(hostname, cluster, secret_key)


@mcp.tool()
def create_infra_env(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                     offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                     key: str = None, force: bool = False, overrides: dict = {}):
    """Create infraenv"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.create_infra_env(infraenv, overrides)


@mcp.tool()
def delete_infra_env(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                     offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                     key: str = None, force: bool = False):
    """Delete infraenv"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.delete_infra_env(infraenv, force=force)


@mcp.tool()
def info_infra_env(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                   offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                   key: str = None, full: bool = False, fields: list = []) -> dict:
    """Provide information on infraenv"""
    if not full:
        skipped = ['kind', 'href', 'ssh_public_key', 'http_proxy', 'https_proxy', 'no_proxy', 'pull_secret_set',
                   'vip_dhcp_allocation', 'validations_info', 'hosts', 'image_info', 'host_networks']
    else:
        skipped = []
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    info = ai.info_infra_env(infraenv).to_dict()
    if fields:
        for key in list(info):
            if key not in fields:
                del info[key]
    for key in list(info):
        if key in skipped or info[key] is None:
            del info[key]
    return info


@mcp.tool()
def list_infra_envs(url: str = "https://api.openshift.com", token: str = None,
                    offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                    key: str = None) -> list:
    """List infraenvs"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    infra_envs = ai.list_infra_envs()
    cluster_ids = {}
    infra_envs_table = ["Infraenv", "Id", "Cluster", "Openshift Version", "Iso Type"]
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
        infra_envs_table.append(entry)
    return infra_envs_table


@mcp.tool()
def bind_infra_env(infraenv: str, cluster: str, url: str = "https://api.openshift.com", token: str = None,
                   offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                   key: str = None, force: bool = False):
    """Bind infraenv to cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.bind_infra_env(infraenv, cluster, force=force)


@mcp.tool()
def start_infraenv(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                   offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                   key: str = None):
    """Start infraenv"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.start_infraenv(infraenv)


@mcp.tool()
def stop_infraenv(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                  offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                  key: str = None):
    """Stop infraenv"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.stop_infraenv(infraenv)


@mcp.tool()
def unbind_infra_env(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                     offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                     key: str = None):
    """Unbind infraenv"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.unbind_infra_env(infraenv)


@mcp.tool()
def update_infra_env(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                     offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                     key: str = None, overrides: dict = {}):
    """Update infraenv"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.update_infra_env(infraenv, overrides)


@mcp.tool()
def info_static_network_config(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                               offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                               key: str = None) -> str:
    """Provide static network config of cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    static_network_config = ai.info_infra_env(infraenv).to_dict()['static_network_config']
    if static_network_config is not None:
        static_network_config = eval(static_network_config)
        for index, entry in enumerate(static_network_config):
            static_network_config[index]['network_yaml'] = yaml.safe_load(entry['network_yaml'])
        return (yaml.safe_dump(static_network_config))


@mcp.tool()
def info_iso(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
             offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
             key: str = None, overrides: dict = {}, minimal: bool = False) -> str:
    """Provide discovery iso url of infraenv/cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    iso_url = ai.info_iso(infraenv, overrides, minimal=minimal)
    return iso_url


@mcp.tool()
def download_iso(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                 offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                 key: str = None, path: str = '.'):
    """Download discovery iso of infraenv/cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.download_iso(infraenv, path)


@mcp.tool()
def download_kubeadminpassword(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                               offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                               key: str = None, stdout: bool = True, path: str = '.') -> str:
    """Download kubeadminpassword of cluster"""
    if not stdout:
        path = f"{path}/kubeadmin-password.{cluster}"
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.download_kubeadminpassword(cluster, path, stdout=stdout)


@mcp.tool()
def download_kubeconfig(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                        offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                        key: str = None, stdout: bool = True, path: str = '.') -> str:
    """Download kubeconfig of cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.download_kubeconfig(cluster, path, stdout=stdout)


@mcp.tool()
def download_initrd(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                    offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                    key: str = None, path: str = '.'):
    """Download initrd of infraenv/cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.download_initrd(infraenv, path)


@mcp.tool()
def download_installconfig(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                           offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                           key: str = None, stdout: bool = True, path: str = '.') -> str:
    """Download installconfig cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.download_installconfig(cluster, path, stdout=stdout)


@mcp.tool()
def download_ignition(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                      offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                      key: str = None, role: str = 'worker', path: str = '.'):
    """Download ignition of cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.download_ignition(cluster, path, role=role)


@mcp.tool()
def download_discovery_ignition(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                                offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                                key: str = None, path: str = '.'):
    """Download discovery ignition of infraenv"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.download_discovery_ignition(infraenv, path)


@mcp.tool()
def download_ipxe_script(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                         offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                         key: str = None, path: str = '.', serve: bool = False, local: bool = True):
    """Download ipxe script of infraenv"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    local = True if serve else local
    ai.download_ipxe_script(infraenv, path, local=local, serve=serve)


@mcp.tool()
def download_manifests(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                       offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                       key: str = None, path: str = '.'):
    """Download manifests of cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.download_manifests(cluster, path)


@mcp.tool()
def download_static_networking_config(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
                                      offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                                      key: str = None, path: str = '.'):
    """Download static network config of infraenv/cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.download_static_networking_config(infraenv, path)


@mcp.tool()
def bind_host(hostname: str, cluster: str, url: str = "https://api.openshift.com", token: str = None,
              offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
              key: str = None):
    """Bind host to cluster"""
    overrides = {'cluster': cluster}
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.update_host(hostname, overrides)


@mcp.tool()
def unbind_host(hostname: str, url: str = "https://api.openshift.com", token: str = None,
                offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                key: str = None):
    """Unbind host to cluster"""
    overrides = {'cluster': None}
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.update_host(hostname, overrides)


@mcp.tool()
def update_host(hostnames: list = [], url: str = "https://api.openshift.com", token: str = None,
                offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                key: str = None, overrides: dict = {}):
    """Update hosts"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.update_hosts(hostnames, overrides)


@mcp.tool()
def wait_hosts(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
               offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
               key: str = None, filter_installed: bool = True, number: int = 3):
    """Wait for hosts"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.wait_hosts(infraenv, number, filter_installed=filter_installed)


@mcp.tool()
def wait_cluster(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                 offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                 key: str = None, status: str = 'installed'):
    """Wait for cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.wait_cluster(cluster, status)


@mcp.tool()
def list_manifests(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                   offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                   key: str = None) -> list:
    """List manifests of cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    manifests = ai.list_manifests(cluster)
    manifeststable = ["File", "Folder"]
    for manifest in sorted(manifests, key=lambda x: x['file_name']):
        filename = manifest['file_name']
        folder = manifest['folder']
        entry = [filename, folder]
        manifeststable.append(entry)
    return manifeststable


@mcp.tool()
def update_installconfig(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                         offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                         key: str = None, overrides: dict = {}):
    """Update installconfig of cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.update_installconfig(cluster, overrides)


@mcp.tool()
def update_iso(infraenv: str, url: str = "https://api.openshift.com", token: str = None,
               offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
               key: str = None, overrides: dict = {}):
    """Update iso of infraenv/cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.update_iso(infraenv, overrides)


@mcp.tool()
def info_service(url: str = "https://api.openshift.com", token: str = None,
                 offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                 key: str = None):
    """Provide information on service"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    ai.info_service()


@mcp.tool()
def list_events(cluster: str, url: str = "https://api.openshift.com", token: str = None,
                offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                key: str = None, follow: bool = False) -> list:
    """List events of cluster"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    events = ai.list_events(cluster)
    eventstable = ["Date", "Message"]
    for event in events:
        date = event['event_time']
        message = event['message']
        entry = [date, message]
        eventstable.append(entry)
    return eventstable


def list_all_keywords(url: str = "https://api.openshift.com", token: str = None,
                      offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                      key: str = None) -> list:
    """List all keywords"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    cluster_keywords = ai.get_cluster_keywords()
    infra_keywords = ai.get_infraenv_keywords()
    host_keywords = ai.get_host_keywords()
    extra_keywords = ai.get_extra_keywords()
    keywordstable = ["Keyword"]
    for keyword in sorted(cluster_keywords + infra_keywords + host_keywords + extra_keywords):
        keywordstable.append([keyword])
    return keywordstable


@mcp.tool()
def list_infraenv_keywords(url: str = "https://api.openshift.com", token: str = None,
                           offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                           key: str = None) -> list:
    """List infraenv keywords"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    keywords = ai.get_infraenv_keywords()
    keywordstable = ["Keyword"]
    for keyword in sorted(keywords):
        keywordstable.append([keyword])
    return keywordstable


@mcp.tool()
def list_cluster_keywords(url: str = "https://api.openshift.com", token: str = None,
                          offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                          key: str = None) -> list:
    """List cluster keywords"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    keywords = ai.get_cluster_keywords()
    keywordstable = ["Keyword"]
    for keyword in sorted(keywords):
        keywordstable.append([keyword])
    return keywordstable


@mcp.tool()
def list_host_keywords(url: str = "https://api.openshift.com", token: str = None,
                       offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                       key: str = None) -> list:
    """List host keywords"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    keywords = ai.get_host_keywords()
    keywordstable = ["Keyword"]
    for keyword in sorted(keywords):
        keywordstable.append([keyword])
    return keywordstable


@mcp.tool()
def list_extra_keywords(url: str = "https://api.openshift.com", token: str = None,
                        offlinetoken: str = None, debug: bool = False, ca: str = None, cert: str = None,
                        key: str = None) -> list:
    """"List extra keywords"""
    ai = AssistedClient(url, token=token, offlinetoken=offlinetoken, debug=debug, ca=ca, cert=cert, key=key)
    keywords = ai.get_extra_keywords()
    keywordstable = ["Keyword"]
    for keyword in sorted(keywords):
        keywordstable.append([keyword])
    return keywordstable


@mcp.tool()
def create_onprem(debug: bool = False, overrides: dict = {}):
    "Create onprem deployment"
    ai_create_onprem(overrides, debug=debug)


@mcp.tool()
def delete_onprem(debug: bool = False, overrides: dict = {}):
    """Delete onprem deployment"""
    ai_delete_onprem(overrides, debug=debug)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
