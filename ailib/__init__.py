from assisted_service_client import ApiClient, Configuration, api, models
from ailib.common import warning, error, info, get_token, match_mac
from ailib.kfish import Redfish
import base64
from datetime import datetime
import http.server
from ipaddress import ip_network
import json
import os
import re
from shutil import copyfileobj, move
import socket
import socketserver
from subprocess import call
import sys
from tempfile import TemporaryDirectory
from time import sleep
from uuid import uuid1
import urllib
from urllib.parse import urlparse
from urllib.request import urlretrieve
import yaml
import traceback

default_cluster_params = {"openshift_version": "4.15", "base_dns_domain": "karmalabs.corp",
                          "vip_dhcp_allocation": False}
default_cluster_params = {"openshift_version": "4.15", "vip_dhcp_allocation": False}
default_infraenv_params = {"openshift_version": "4.15", "image_type": "full-iso"}
SSH_PUB_LOCATIONS = ['id_ed25519.pub', 'id_ecdsa.pub', 'id_dsa.pub', 'id_rsa.pub']


def normalize_proxy(proxy):
    return f'http://{proxy}' if not proxy.startswith('http') else proxy


def boot_hosts(overrides, hostnames=[], debug=False):
    if 'hosts' not in overrides:
        warning("No hosts to boot found in your parameter file")
        return 1
    iso_url = overrides['iso_url']
    if iso_url is None:
        warning("Missing iso_url in your parameters")
        return 1
    elif not iso_url.endswith('.iso') and 'image_token=' not in iso_url:
        cluster = overrides.get('cluster')
        if cluster is None:
            warning("Missing cluster name in your parameters to append it to iso_url")
            return 1
        iso_url += f"/{cluster}.iso"
    hosts = overrides['hosts']
    for index, host in enumerate(hosts):
        hostname = host.get('name', '')
        if hostnames and hostname not in hostnames:
            warning(f"host {hostname} not in {hostnames}. Skipping")
            continue
        bmc_url = host.get('bmc_url') or host.get('url')
        bmc_user = host.get('bmc_user') or host.get('user') or overrides.get('bmc_user')
        bmc_password = host.get('bmc_password') or host.get('password') or overrides.get('bmc_password')
        bmc_reset = host.get('reset') or host.get('bmc_reset') or overrides.get('bmc_reset', False)
        if bmc_url is not None:
            red = Redfish(bmc_url, bmc_user, bmc_password, debug=debug)
            if bmc_reset:
                red.reset()
                sleep(240)
            msg = host['name'] if 'name' in host else f"with url {bmc_url}"
            info(f"Booting Host {msg}")
            try:
                red.set_iso(iso_url)
            except Exception as e:
                warning(f"Hit {e} when plugging iso to host {msg}")
                if debug:
                    traceback.print_exception(e)
                return 1
        else:
            warning(f"Skipping entry {index} because either bmc_url, bmc_user or bmc_password is not set")
        if 'sno' in overrides and overrides['sno']:
            info("Not booting more hosts since you asked for an SNO")
            break
    return 0


class AssistedClient(object):
    def __init__(self, url='https://api.openshift.com', token=None, offlinetoken=None, debug=False,
                 ca=None, cert=None, key=None, quiet=False):
        self.quiet = quiet
        self.url = url
        self.config = Configuration()
        self.config.host = self.url + "/api/assisted-install"
        self.config.verify_ssl = False
        if ca is not None:
            if '-----BEGIN CERTIFICATE-----' not in ca:
                ca_file = os.path.expanduser(ca)
                if os.path.exists(ca_file):
                    ca = open(ca_file).read()
                else:
                    error(f'{ca_file} file not found')
                    sys.exit(1)
            self.config.ssl_ca_cert = ca
        if cert is not None:
            cert_file = os.path.expanduser(cert)
            if not os.path.exists(cert_file):
                error(f'{cert_file} file not found')
                sys.exit(1)
            self.config.cert_file = cert_file
        if key is not None:
            key_file = os.path.expanduser(key)
            if not os.path.exists(key_file):
                error(f'{key_file} file not found')
                sys.exit(1)
            self.config.key_file = key_file
        self.config.debug = debug
        self.saas = True if url in ['https://api.openshift.com', 'https://api.stage.openshift.com',
                                    'https://api.integration.openshift.com'] else False
        proxies = urllib.request.getproxies()
        proxy = proxies.get('https') or proxies.get('http')
        no_proxy = proxies.get('no', 'xxx')
        hostname = urlparse(url).hostname or url.split(':')[0]
        if proxy is not None and hostname not in no_proxy:
            if 'http' not in proxy:
                proxy = "http://" + proxy
                warning(f"Detected proxy env var without scheme, updating proxy to {proxy}")
            self.config.proxy = proxy
        aihome = f"{os.environ['HOME']}/.aicli"
        offlinetokenpath = f'{aihome}/offlinetoken.txt'
        tokenpath = f'{aihome}/token.txt'
        if not os.path.exists(aihome):
            os.mkdir(aihome)
        if self.saas:
            if offlinetoken is None:
                if os.path.exists(offlinetokenpath):
                    offlinetoken = open(offlinetokenpath).read().strip()
                else:
                    error(f"offlinetoken needs to be set to gather token for {url}")
                    error("get it at https://cloud.redhat.com/openshift/token")
                    if os.path.exists('/i_am_a_container'):
                        error("use -e AI_OFFLINETOKEN=$AI_OFFLINETOKEN to expose it in container mode")
                    sys.exit(1)
            elif os.path.exists(offlinetokenpath) and open(offlinetokenpath).read().strip() != offlinetoken:
                error(f"Moving wrong offlinetoken file to {offlinetokenpath}.old")
                move(offlinetokenpath, "{offlinetokenpath}.old")
                if os.path.exists(tokenpath):
                    os.remove(tokenpath)
            if not os.path.exists(offlinetokenpath):
                with open(offlinetokenpath, 'w') as f:
                    f.write(offlinetoken)
            self.offlinetoken = offlinetoken
            self.token = token
            if os.path.exists(tokenpath):
                self.token = open(tokenpath).read().strip()
            try:
                self.token = get_token(token=self.token, offlinetoken=self.offlinetoken)
            except Exception as e:
                error(f"Hit issue when trying to set token. Got {e}")
                if os.path.exists(offlinetokenpath):
                    error(f"Moving wrong offlinetoken file to {offlinetokenpath}.old")
                    move(offlinetokenpath, "{offlinetokenpath}.old")
                sys.exit(1)
            self.config.api_key['Authorization'] = self.token
            self.config.api_key_prefix['Authorization'] = 'Bearer'
        else:
            self.offlinetoken = None
            self.token = None
        self.api = ApiClient(configuration=self.config)
        self.client = api.InstallerApi(api_client=self.api)
        self.debug = debug

    def refresh_token(self, token, offlinetoken):
        if not self.saas:
            return
        self.token = get_token(token=self.token, offlinetoken=self.offlinetoken)
        self.config.api_key['Authorization'] = self.token
        self.api = ApiClient(configuration=self.config)
        self.client = api.InstallerApi(api_client=self.api)

    def _allowed_parameters(self, instance):
        return [a for a in instance.__init__.__code__.co_varnames if a != 'self']

    def get_cluster_keywords(self):
        return self._allowed_parameters(models.ClusterCreateParams)

    def get_infraenv_keywords(self):
        return self._allowed_parameters(models.InfraEnvCreateParams)

    def get_host_keywords(self):
        allowed = self._allowed_parameters(models.HostUpdateParams)
        allowed.extend(self._allowed_parameters(models.InstallerArgsParams))
        return allowed

    @staticmethod
    def get_default_ssh_pub():
        sshdir = '%s/.ssh/' % os.environ['HOME']
        pubpath = f"{sshdir}/id_rsa.pub"
        for path in SSH_PUB_LOCATIONS:
            current_path = f"{sshdir}/{path}"
            if os.path.exists(current_path):
                pubpath = current_path
                break
        return pubpath

    def set_default_values(self, overrides, existing=False, quiet=False):
        if 'openshift_version' in overrides:
            if isinstance(overrides['openshift_version'], float):
                overrides['openshift_version'] = str(overrides['openshift_version'])
            if overrides['openshift_version'] == 4.1:
                overrides['openshift_version'] = '4.10'
        api_vips = overrides.get('api_vips', [])
        api_vip = overrides.get('api_vip') or overrides.get('api_ip')
        if api_vip is not None:
            if 'api_vip' in overrides:
                del overrides['api_vip']
            if api_vip not in api_vips:
                api_vips.append({'ip': api_vip})
                overrides['api_vips'] = api_vips
        new_api_vips = []
        for entry in api_vips:
            new_api_vips.append({'ip': entry} if not isinstance(entry, dict) else entry)
        if new_api_vips:
            overrides['api_vips'] = new_api_vips
        ingress_vips = overrides.get('ingress_vips', [])
        ingress_vip = overrides.get('ingress_vip') or overrides.get('ingress_ip')
        if ingress_vip is not None:
            if 'ingress_vip' in overrides:
                del overrides['ingress_vip']
            if ingress_vip not in ingress_vips:
                ingress_vips.append({'ip': ingress_vip})
                overrides['ingress_vips'] = ingress_vips
        new_ingress_vips = []
        for entry in ingress_vips:
            new_ingress_vips.append({'ip': entry} if not isinstance(entry, dict) else entry)
        if new_ingress_vips:
            overrides['ingress_vips'] = new_ingress_vips
        if not existing:
            if 'pull_secret' not in overrides:
                warning("Using openshift_pull.json as pull_secret file", quiet=quiet)
                overrides['pull_secret'] = "openshift_pull.json"
            pull_secret = os.path.expanduser(overrides['pull_secret'])
            if os.path.exists(pull_secret):
                overrides['pull_secret'] = re.sub(r"\s", "", open(pull_secret).read())
            elif '{' not in pull_secret:
                error(f"Couldn't parse pull secret file {pull_secret}")
                sys.exit(1)
            if 'ssh_public_key' not in overrides:
                pub_key = overrides.get('public_key', self.get_default_ssh_pub())
                if os.path.exists(pub_key):
                    overrides['ssh_public_key'] = open(pub_key).read().strip()
                else:
                    error(f"Missing public key file {pub_key}")
                    sys.exit(1)
            if 'domain' in overrides:
                overrides['base_dns_domain'] = overrides['domain']
            elif 'base_dns_domain' not in overrides:
                warning("Using karmalabs.corp as DNS domain as no one was provided", quiet=quiet)
                overrides['base_dns_domain'] = 'karmalabs.corp'
        hosts_number = len(overrides.get('hosts', []))
        if hosts_number == 1 or ('sno' in overrides and overrides['sno']):
            overrides['high_availability_mode'] = "None"
            overrides['user_managed_networking'] = True
            if 'api_vip' in overrides:
                warning("Removing api_vip since SNO is set", quiet=quiet)
                del overrides['api_vip']
            if 'ingress_vip' in overrides:
                warning("Removing ingress_vip since SNO is set", quiet=quiet)
                del overrides['ingress_vip']
        if 'high_availability_mode' in overrides and overrides['high_availability_mode'] is None:
            overrides['high_availability_mode'] = "None"
        if 'olm_operators' in overrides:
            overrides['olm_operators'] = self.set_olm_operators(overrides['olm_operators'])
        if 'tpm' in overrides and overrides['tpm']:
            overrides['disk_encryption'] = {"enable_on": "all", "mode": "tpmv2"}
        if 'tang_servers' in overrides:
            tang_servers = overrides['tang_servers']
            if isinstance(tang_servers, list):
                tang_servers = ','.join(tang_servers)
            overrides['disk_encryption'] = {"enable_on": "all", "mode": "tpmv2", "tang_servers": tang_servers}
        tags = overrides.get('tags', [])
        if not isinstance(tags, list):
            tags = str(tags).split(',')
        if self.saas and 'aicli' not in tags:
            tags.append('aicli')
        if tags:
            overrides['tags'] = ','.join(sorted(tags))
        if 'platform' in overrides and isinstance(overrides['platform'], str):
            platform = overrides['platform']
            valid_platforms = ['baremetal', 'nutanix', 'vsphere', 'none', 'oci']
            if platform not in valid_platforms:
                error(f"Invalid platform. Should belong in {valid_platforms}")
                sys.exit(1)
            platform = {"type": platform}
            overrides['platform'] = platform
        if 'ocp_release_image' in overrides and not overrides['ocp_release_image'].startswith('quay.io'):
            overrides['registry_url'] = overrides['ocp_release_image'].split('/')[0]
        url = overrides.get('disconnected_url') or overrides.get('registry_url')
        if url is not None:
            disconnected_registries = [{'mirrors': [f"{url}/edge-infrastructure"],
                                        "source": "quay.io/edge-infrastructure"},
                                       {'mirrors': [f"{url}/openshift/release", f"{url}/openshift/release-images"],
                                        "source": "quay.io/openshift-release-dev/ocp-release"},
                                       {'mirrors': [f"{url}/openshift/release", f"{url}/openshift/release-images"],
                                        "source": "quay.io/openshift-release-dev/ocp-v4.0-art-dev"}]
            installconfig = {'ImageDigestSources': disconnected_registries}
            info(f"Trying to gather registry ca cert from {url}")
            cacmd = f"openssl s_client -showcerts -connect {url} </dev/null 2>/dev/null|"
            cacmd += "openssl x509 -outform PEM"
            installconfig['additionalTrustBundle'] = os.popen(cacmd).read()
            overrides['installconfig'] = installconfig

    def set_default_infraenv_values(self, overrides):
        if 'cluster' in overrides:
            cluster_id = self.get_cluster_id(overrides['cluster'])
            overrides['cluster_id'] = cluster_id
        if 'minimal' in overrides:
            image_type = "minimal-iso" if overrides['minimal'] else 'full-iso'
            overrides['image_type'] = image_type
        static_network_config = overrides.get('static_network_config', [])
        if static_network_config:
            if isinstance(static_network_config, dict):
                static_network_config = [static_network_config]
            final_network_config = []
            for entry in static_network_config:
                interface_map = []
                bonds = []
                nics = []
                mac_interface_map = entry.get('mac_interface_map', [])
                interfaces = entry.get('interfaces', [])
                if entry.get('network_yaml') is not None:
                    final_network_config.append(models.HostStaticNetworkConfig(**entry))
                    continue
                if not interfaces:
                    error("You need to provide a list of interfaces")
                    sys.exit(1)
                for interface in interfaces:
                    interface_type = interface.get('type', 'ethernet')
                    if interface_type == 'ethernet':
                        logical_nic_name, mac_address = interface['name'], interface['mac-address']
                        interface_map.append({"mac_address": mac_address, "logical_nic_name": logical_nic_name})
                    elif interface_type == 'bond' and 'link-aggregation' in interface\
                            and 'port' in interface['link-aggregation']:
                        bonds.append(interface['name'])
                        for port in interface['link-aggregation']['port']:
                            nics.append(port)
                    elif interface_type == 'vlan' and 'vlan' in interface and 'base-iface' in interface['vlan']:
                        nics.append(interface['vlan']['base-iface'])
                mac_interface_map = mac_interface_map or interface_map
                mac_interface_map_nics = [interface['logical_nic_name'] for interface in mac_interface_map]
                for nic in nics:
                    if nic not in bonds and nic not in mac_interface_map_nics:
                        error(f"Nic {nic} is missing from mac_interface_map")
                        sys.exit(1)
                new_entry = {'network_yaml': yaml.dump(entry), 'mac_interface_map': mac_interface_map}
                final_network_config.append(models.HostStaticNetworkConfig(**new_entry))
            static_network_config = final_network_config
            overrides['static_network_config'] = static_network_config
        if 'ssh_authorized_key' not in overrides:
            if 'ssh_public_key' in overrides:
                overrides['ssh_authorized_key'] = overrides['ssh_public_key']
            else:
                pub_key = overrides.get('public_key', self.get_default_ssh_pub())
                if os.path.exists(pub_key):
                    overrides['ssh_authorized_key'] = open(pub_key).read().strip()
                else:
                    error(f"Missing public key file {pub_key}")
                    sys.exit(1)
        if 'ignition_config_override' not in overrides:
            iso_overrides = overrides.copy()
            iso_overrides['ignition_version'] = '3.1.0'
            ignition_config_override = self.set_disconnected_ignition_config_override(infra_env_id=None,
                                                                                      overrides=iso_overrides)
            if ignition_config_override is not None:
                overrides['ignition_config_override'] = ignition_config_override
        if 'discovery_ignition_file' in overrides:
            discovery_ignition_path = overrides['discovery_ignition_file']
            if not os.path.exists(discovery_ignition_path):
                warning(f"Ignition File {discovery_ignition_path} not found. Ignoring")
            else:
                overrides['ignition_config_override'] = open(discovery_ignition_path).read()
        proxy, http_proxy, https_proxy = None, None, None
        if 'proxy' in overrides and isinstance(overrides['proxy'], str):
            proxy = normalize_proxy(overrides['proxy'])
        if 'http_proxy' in overrides and isinstance(overrides['http_proxy'], str):
            http_proxy = normalize_proxy(overrides['http_proxy'])
        if 'https_proxy' in overrides and isinstance(overrides['https_proxy'], str):
            https_proxy = normalize_proxy(overrides['https_proxy'])
        if proxy is not None or http_proxy is not None or https_proxy is not None:
            http_proxy = proxy or https_proxy or http_proxy
            https_proxy = proxy or http_proxy or https_proxy
            overrides['proxy'] = {'http_proxy': http_proxy, 'https_proxy': https_proxy}
            if 'noproxy' in overrides:
                overrides['proxy']['no_proxy'] = overrides['noproxy']
        if 'kernel_arguments' in overrides:
            kernel_arguments = overrides['kernel_arguments']
            if isinstance(kernel_arguments, str):
                kernel_arguments = kernel_arguments.split(" ")
            overrides['kernel_arguments'] = []
            for entry in kernel_arguments:
                if isinstance(entry, dict):
                    new_entry = entry
                else:
                    new_entry = {'operation': 'append', 'value': entry}
                overrides['kernel_arguments'].append(models.KernelArgument(**new_entry))

    def set_disconnected_ignition_config_override(self, infra_env_id=None, overrides={}):
        ignition_config_override = None
        disconnected_url = overrides.get('disconnected_url') or overrides.get('registry_url')
        if disconnected_url is not None and ':' not in disconnected_url:
            disconnected_url += ':443'
        ca = overrides.get('disconnected_ca')
        if ca is None:
            if 'installconfig' in overrides and isinstance(overrides['installconfig'], dict)\
                    and 'additionalTrustBundle' in overrides['installconfig']:
                info("Using cert from installconfig/additionalTrustBundle")
                ca = overrides['installconfig']['additionalTrustBundle']
            elif disconnected_url is not None and 'quay.io' not in disconnected_url:
                info(f"Trying to gather registry ca cert from {disconnected_url}")
                cacmd = f"openssl s_client -showcerts -connect {disconnected_url} </dev/null 2>/dev/null|"
                cacmd += "openssl x509 -outform PEM"
                ca = os.popen(cacmd).read()
        if 'ignition_config_override' not in overrides and disconnected_url is not None and ca is not None:
            ignition_version = overrides.get('ignition_version')
            if ignition_version is None:
                ori = self.client.v2_download_infra_env_files(infra_env_id=infra_env_id, file_name="discovery.ign",
                                                              _preload_content=False)
                ignition_version = json.loads(ori.read().decode("utf-8"))['ignition']['version']
            if 'installconfig' in overrides and isinstance(overrides['installconfig'], dict)\
                    and 'ImageDigestSources' in overrides['installconfig']:
                info("Using ImageDigestSources from installconfig")
                registries = 'unqualified-search-registries = ["registry.access.redhat.com", "docker.io"]\n'
                for registry in overrides['installconfig']['ImageDigestSources']:
                    source = registry.get('source')
                    for target in registry.get('mirrors', []):
                        new_registry = """[[registry]]
   prefix = ""
   location = "{source}"
   mirror-by-digest-only = false

   [[registry.mirror]]
   location = "{target}"\n""".format(source=source, target=target)
                        registries += new_registry
            else:
                ailibdir = os.path.dirname(warning.__code__.co_filename)
                with open(f"{ailibdir}/registries.conf.templ") as f:
                    data = f.read()
                    registries = data % {'url': disconnected_url}
            registries_encoded = base64.b64encode(registries.encode()).decode("UTF-8")
            ca_encoded = base64.b64encode(ca.encode()).decode("UTF-8")
            fil1 = {"path": "/etc/containers/registries.conf.d/99-mirror.conf", "mode": 420, "overwrite": True,
                    "user": {"name": "root"},
                    "contents": {"source": f"data:text/plain;base64,{registries_encoded}"}}
            fil2 = {"path": "/etc/pki/ca-trust/source/anchors/domain.crt", "mode": 420, "overwrite": True,
                    "user": {"name": "root"}, "contents": {"source": f"data:text/plain;base64,{ca_encoded}"}}
            ignition_config_override = {"ignition": {"version": ignition_version}, "storage": {"files": [fil1, fil2]}}
        if 'password' in overrides:
            info("Creating aicli user with password aicli in the discovery iso")
            password = '$2y$05$OuDf.Q80OWQsK75AAW1oreQnGqDykML9Zq4VW9.J1yqs/2Qlvoun.'
            password_overrides = {'ignition': {'version': "3.1.0"},
                                  "passwd": {'users': [{"groups": ["sudo"], "name":"aicli", 'passwordHash': password}]}}
            if ignition_config_override is not None:
                ignition_config_override.update(password_overrides)
            else:
                ignition_config_override = password_overrides
        if ignition_config_override is not None:
            ignition_config_override = json.dumps(ignition_config_override)
        return ignition_config_override

    def set_olm_operators(self, olm_operators_data):
        operatorsapi = api.OperatorsApi(api_client=self.api)
        supported_operators = operatorsapi.v2_list_supported_operators()
        olm_operators = []
        for operator in olm_operators_data:
            if isinstance(operator, str):
                operator_name = operator
            elif isinstance(operator, dict) and 'name' in operator:
                operator_name = operator['name']
            else:
                error(f"Invalid entry for olm_operator {operator}")
                sys.exit(1)
            if operator_name not in supported_operators:
                error(f"Incorrect olm_operator {operator_name}. Should be one of {supported_operators}")
                sys.exit(1)
            olm_operators.append({'name': operator_name})
        return olm_operators

    def set_cluster_networks(self, cluster_id, cluster_networks_data):
        cluster_networks = []
        for cluster_network in cluster_networks_data:
            host_prefix = None
            if isinstance(cluster_network, str):
                cidr = cluster_network
            elif isinstance(cluster_network, dict) and 'cidr' in cluster_network:
                cidr = cluster_network['cidr']
                host_prefix = cluster_network.get('host_prefix') or cluster_network.get('hostPrefix')
            else:
                error(f"Invalid entry for cluster_network {cluster_network}")
                sys.exit(1)
            try:
                ip_network(cidr)
            except:
                error(f"Invalid cidr for cluster_network {cluster_network}")
                sys.exit(1)
            if host_prefix is None:
                host_prefix = 64 if ':' in cidr else 23
            cluster_networks.append({'cidr': cidr, 'cluster_id': cluster_id, 'host_prefix': host_prefix})
        return cluster_networks

    def set_machine_networks(self, cluster_id, machine_networks_data):
        machine_networks = []
        for machine_network in machine_networks_data:
            if isinstance(machine_network, str):
                cidr = machine_network
            elif isinstance(machine_network, dict) and 'cidr' in machine_network:
                cidr = machine_network['cidr']
            else:
                error(f"Invalid entry for machine_network {machine_network}")
                sys.exit(1)
            try:
                ip_network(cidr)
            except:
                error(f"Invalid cidr for machine_network {machine_network}")
                sys.exit(1)
            machine_networks.append({'cidr': cidr, 'cluster_id': cluster_id})
        return machine_networks

    def set_service_networks(self, cluster_id, service_networks_data):
        service_networks = []
        for service_network in service_networks_data:
            if isinstance(service_network, str):
                cidr = service_network
            elif isinstance(service_network, dict) and 'cidr' in service_network:
                cidr = service_network['cidr']
            else:
                error(f"Invalid entry for service_network {service_network}")
                sys.exit(1)
            try:
                ip_network(cidr)
            except:
                error(f"Invalid cidr for service_network {service_network}")
                sys.exit(1)
            service_networks.append({'cidr': cidr, 'cluster_id': cluster_id})
        return service_networks

    def get_cluster_id(self, name):
        matching_ids = [x['id'] for x in self.list_clusters() if x['name'] == name or x['id'] == name]
        if matching_ids:
            return matching_ids[0]
        else:
            error(f"Cluster {name} not found")
            sys.exit(1)

    def get_cluster_name(self, _id):
        matching_names = [x['name'] for x in self.list_clusters() if x['id'] == _id]
        if matching_names:
            return matching_names[0]
        else:
            error(f"Cluster {_id} not found")
            sys.exit(1)

    def create_cluster(self, name, overrides={}, force=False):
        existing_ids = [x['id'] for x in self.list_clusters() if x['name'] == name]
        if existing_ids:
            if force:
                info(f"Cluster {name} there. Deleting")
                self.delete_cluster(name)
                for infra_env in self.list_infra_envs():
                    infra_env_name = infra_env.get('name')
                    if infra_env_name is not None and infra_env_name == f"{name}_infra-env":
                        self.delete_infra_env(infra_env['id'])
                        break
            else:
                error(f"Cluster {name} already there. Leaving")
                sys.exit(1)
        if name.endswith('-day2'):
            self.create_day2_cluster(name, overrides)
            return
        self.set_default_values(overrides)
        new_cluster_params = default_cluster_params
        new_cluster_params['name'] = name
        update_parameters = ['cluster_networks', 'service_networks', 'machine_networks']
        extra_overrides = {}
        allowed_parameters = self._allowed_parameters(models.ClusterCreateParams)
        for parameter in overrides:
            if parameter == 'network_type' and overrides[parameter] not in ['OpenShiftSDN', 'OVNKubernetes']:
                new_cluster_params['network_type'] = 'OVNKubernetes'
                extra_overrides[parameter] = overrides[parameter]
            elif parameter in update_parameters:
                extra_overrides[parameter] = overrides[parameter]
            elif parameter in allowed_parameters:
                new_cluster_params[parameter] = overrides[parameter]
            else:
                extra_overrides[parameter] = overrides[parameter]
        if self.debug:
            print(new_cluster_params)
        cluster_params = models.ClusterCreateParams(**new_cluster_params)
        result = self.client.v2_register_cluster(new_cluster_params=cluster_params)
        if extra_overrides:
            self.update_cluster(name, extra_overrides)
        info(f"Using version {result.openshift_version}")

    def delete_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        info_cluster = self.info_cluster(cluster_id)
        if info_cluster.to_dict()['status'] == 'installing':
            self.client.v2_reset_cluster(cluster_id=cluster_id)
        self.client.v2_deregister_cluster(cluster_id=cluster_id)
        day2_matching_ids = [x['id'] for x in self.list_clusters() if x['name'] == f'{name}-day2']
        if day2_matching_ids:
            self.client.v2_deregister_cluster(cluster_id=day2_matching_ids[0])

    def info_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        return self.client.v2_get_cluster(cluster_id=cluster_id)

    def preflight_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        return self.client.v2_get_preflight_requirements(cluster_id=cluster_id)

    def export_cluster(self, name):
        allowed_parameters = self._allowed_parameters(models.ClusterCreateParams)
        cluster_id = self.get_cluster_id(name)
        alldata = self.client.v2_get_cluster(cluster_id=cluster_id).to_dict()
        data = {}
        for k in allowed_parameters:
            if k in alldata and alldata[k] is not None:
                data[k] = alldata[k]
            if k == 'disk_encryption' and alldata[k]['enable_on'] is None:
                del data[k]
        print(yaml.dump(data, default_flow_style=False, indent=2))

    def create_day2_cluster(self, name, overrides={}):
        api_vip_dnsname = overrides.get('api_vip_dnsname')
        cluster_name = name.replace('-day2', '')
        cluster_id = None
        existing_ids = [x['id'] for x in self.list_clusters() if x['name'] == cluster_name]
        if not existing_ids:
            warning(f"Base Cluster {cluster_name} not found. Populating with default values")
            if 'version' in overrides:
                openshift_version = overrides['version']
            elif 'openshift_version' in overrides:
                openshift_version = overrides['openshift_version']
            else:
                openshift_version = default_cluster_params["openshift_version"]
                warning(f"No openshift_version provided.Using {openshift_version}")
            if 'domain' in overrides:
                domain = overrides['domain']
                del overrides['domain']
            elif 'base_dns_domain' in overrides:
                domain = overrides['base_dns_domain']
            else:
                domain = default_cluster_params["base_dns_domain"]
                warning(f"No base_dns_domain provided.Using {domain}")
            overrides['base_dns_domain'] = domain
            if api_vip_dnsname is None:
                api_vip_dnsname = f"api.{cluster_name}.{domain}"
            try:
                socket.gethostbyname(api_vip_dnsname)
            except:
                warning(f"{api_vip_dnsname} doesn't resolve")
                warning(f"run aicli update cluster {name} -P api_vip_dnsname=$api_ip")
            self.set_default_values(overrides)
            pull_secret, ssh_public_key = overrides['pull_secret'], overrides['ssh_public_key']
        else:
            cluster_id = self.get_cluster_id(cluster_name)
            cluster = self.client.v2_get_cluster(cluster_id=cluster_id)
            openshift_version = cluster.openshift_version
            ssh_public_key = cluster.image_info.ssh_public_key
            if api_vip_dnsname is None:
                api_vip_dnsname = cluster.api_vips[0].ip
                warning(f"Forcing api_vip_dnsname to {api_vip_dnsname}")
            response = self.client.v2_download_cluster_files(cluster_id=cluster_id, file_name="install-config.yaml",
                                                             _preload_content=False)
            data = yaml.safe_load(response.read().decode("utf-8"))
            pull_secret = data.get('pullSecret')
        if cluster_id is None:
            cluster_id = str(uuid1())
        new_import_cluster_params = {"name": name, "openshift_version": str(openshift_version),
                                     "api_vip_dnsname": api_vip_dnsname, 'openshift_cluster_id': cluster_id}
        new_import_cluster_params = models.ImportClusterParams(**new_import_cluster_params)
        self.client.v2_import_cluster(new_import_cluster_params=new_import_cluster_params)
        cluster_update_params = {'pull_secret': pull_secret, 'ssh_public_key': ssh_public_key}
        cluster_update_params = models.V2ClusterUpdateParams(**cluster_update_params)
        new_cluster_id = self.get_cluster_id(name)
        self.client.v2_update_cluster(cluster_id=new_cluster_id, cluster_update_params=cluster_update_params)

    def _expired_iso(self, iso_url):
        search = re.search(r".*&image_token=(.*)&type=.*", iso_url)
        if search is None:
            search = re.search(r".*/bytoken/(.*?)/.*", iso_url)
        if search is not None:
            encoded_token = search.group(1)
            token = str(base64.urlsafe_b64decode(encoded_token + '==='))
            expiration_date = int(re.search(r'.*"exp":(.*),"sub".*"', token).group(1))
            if datetime.fromtimestamp(expiration_date) < datetime.now():
                return True
            else:
                return False
        else:
            error("couldn't parse iso_url")
            sys.exit(1)

    def info_iso(self, name, overrides, minimal=False):
        infra_env = self.info_infra_env(name).to_dict()
        iso_url = infra_env['download_url']
        if self.saas and self._expired_iso(iso_url):
            iso_url = self.client.get_infra_env_download_url(infra_env['id']).url
        return iso_url

    def download_iso(self, name, path):
        infra_env = self.info_infra_env(name).to_dict()
        iso_url = infra_env['download_url']
        if self.saas and self._expired_iso(iso_url):
            warning("Generating new iso url")
            iso_url = self.client.get_infra_env_download_url(infra_env['id']).url
        urlretrieve(iso_url, f"{path}/{name}.iso")

    def download_initrd(self, name, path):
        print("not implemented")
        return
        infra_env_id = self.get_infra_env_id(name)
        response = self.client.download_minimal_initrd(infra_env_id=infra_env_id, _preload_content=False)
        with open(f"{path}/initrd.{name}", "wb") as f:
            for line in response:
                f.write(line)

    def download_installconfig(self, name, path, stdout=False):
        cluster_id = self.get_cluster_id(name)
        response = self.client.v2_get_cluster_install_config(cluster_id=cluster_id)
        if stdout:
            print(response)
        else:
            installconfig_path = f"{path}/install-config.yaml.{name}"
            with open(installconfig_path, "w") as f:
                f.write(response)

    def download_kubeadminpassword(self, name, path, stdout=False):
        cluster_id = self.get_cluster_id(name)
        response = self.client.v2_download_cluster_credentials(cluster_id=cluster_id, file_name="kubeadmin-password",
                                                               _preload_content=False)
        if stdout:
            print(response.data.decode())
        else:
            kubeadminpassword_path = f"{path}/kubeadmin-password.{name}"
            with open(kubeadminpassword_path, "wb") as f:
                copyfileobj(response, f)

    def download_kubeconfig(self, name, path, stdout=False):
        cluster_id = self.get_cluster_id(name)
        response = self.client.v2_download_cluster_credentials(cluster_id=cluster_id, file_name="kubeconfig-noingress",
                                                               _preload_content=False)
        if stdout:
            print(response.data.decode())
        else:
            kubeconfig_path = f"{path}/kubeconfig.{name}"
            with open(kubeconfig_path, "wb") as f:
                copyfileobj(response, f)

    def download_discovery_ignition(self, name, path):
        infra_env_id = self.get_infra_env_id(name)
        response = self.client.v2_download_infra_env_files(infra_env_id=infra_env_id, file_name="discovery.ign",
                                                           _preload_content=False)
        with open(f"{path}/discovery.ign.{name}", "wb") as f:
            copyfileobj(response, f)

    def download_ignition(self, name, path, role='bootstrap'):
        cluster_id = self.get_cluster_id(name)
        response = self.client.v2_download_cluster_files(cluster_id=cluster_id, file_name=f"{role}.ign",
                                                         _preload_content=False)
        with open(f"{path}/{role}.ign.{name}", "wb") as f:
            copyfileobj(response, f)

    def download_ipxe_script(self, name, path, local=False, serve=False):
        infra_env_id = self.get_infra_env_id(name)
        response = self.client.v2_download_infra_env_files(infra_env_id=infra_env_id, file_name="ipxe-script",
                                                           _preload_content=False)
        with open(f"{path}/ipxe-script.{name}", "wb") as f:
            copyfileobj(response, f)
        if local:
            info("Making assets available locally")
            if serve:
                route = os.popen("ip route get 1").read().split(' ')
                ip = route[route.index('src') + 1].strip()
            else:
                ip = "$IP"
            kernel, initrd = None, None
            with open(f"{path}/ipxe-script-local.{name}", "w") as dest:
                newkernel = f"http://{ip}/kernel.{name}"
                newinitrd = f"http://{ip}/initrd.{name}"
                for line in open(f"{path}/ipxe-script.{name}", "r").readlines():
                    newline = line
                    if line.startswith('kernel'):
                        for entry in line.split(' '):
                            if entry.startswith('https'):
                                kernel = entry
                        newline = line.replace(kernel, newkernel)
                    if line.startswith('initrd'):
                        initrd = line.split(' ')[1]
                        newline = line.replace(initrd, newinitrd)
                    dest.write(newline)
            if kernel is None or initrd is None:
                error("Couldn't properly parse the ipxe-script")
            else:
                if not os.path.exists(f"{path}/kernel.{name}"):
                    info("Downloading kernel")
                    urlretrieve(kernel, f"{path}/kernel.{name}")
                if not os.path.exists(f"{path}/initrd.{name}"):
                    info("Downloading initrd")
                    urlretrieve(initrd, f"{path}/initrd.{name}")
            if serve:
                os.chdir(path)
                PORT = 8000
                info(f"Serving those assets from http://{ip}:{PORT}")
                handler = http.server.SimpleHTTPRequestHandler
                with socketserver.TCPServer(("", PORT), handler) as httpd:
                    httpd.serve_forever()

    def download_static_networking_config(self, name, path):
        infra_env_id = self.get_infra_env_id(name)
        response = self.client.v2_download_infra_env_files(infra_env_id=infra_env_id, file_name="static-network-config",
                                                           _preload_content=False)
        with open(f"{path}/static-network-config.{name}.tar", "wb") as f:
            copyfileobj(response, f)

    def list_clusters(self):
        return self.client.v2_list_clusters()

    def list_hosts(self):
        allhosts = []
        for infra_env in self.client.list_infra_envs():
            infra_env_id = infra_env['id']
            hosts = self.client.v2_list_hosts(infra_env_id=infra_env_id)
            allhosts.extend(hosts)
        return allhosts

    def delete_host(self, hostname, overrides={}):
        infra_envs = {}
        if 'infraenv' in overrides:
            infraenv = overrides['infraenv']
            infra_env_id = self.get_infra_env_id(infraenv)
            hosts = self.client.v2_list_hosts(infra_env_id=infra_env_id)
            matchingids = [host['id'] for host in hosts
                           if host['requested_hostname'] == hostname or host['id'] == hostname]
        else:
            for infra_env in self.client.list_infra_envs():
                infra_env_id = infra_env['id']
                hosts = self.client.v2_list_hosts(infra_env_id=infra_env_id)
                matchingids = [host['id'] for host in hosts
                               if host['requested_hostname'] == hostname or host['id'] == hostname]
                if matchingids:
                    infra_envs[infra_env_id] = matchingids
        if not infra_envs:
            error(f"No Matching Host with name {hostname} found")
        for infra_env_id in infra_envs:
            host_ids = infra_envs[infra_env_id]
            for host_id in host_ids:
                info(f"Deleting Host with id {host_id} in infraenv {infra_env_id}")
                self.client.v2_deregister_host(infra_env_id, host_id)

    def info_host(self, hostname):
        hostinfo = None
        for infra_env in self.client.list_infra_envs():
            infra_env_id = infra_env['id']
            infra_env_hosts = self.client.v2_list_hosts(infra_env_id=infra_env_id)
            hosts = [h for h in infra_env_hosts if h['requested_hostname'] == hostname or h['id'] == hostname]
            if hosts:
                hostinfo = hosts[0]
                break
        return hostinfo

    def update_hosts(self, hostnames=[], overrides={}):
        host_param_overrides = {}
        if 'hosts' in overrides:
            host_param_overrides = overrides['hosts']
            if not hostnames:
                hostnames = [h.get('mac') or h.get('id') or h.get('name') for h in host_param_overrides if
                             'mac' in h or 'id' in h or 'name' in h]
        if not hostnames:
            warning("No hosts provided to update")
            return
        for index, hostname in enumerate(hostnames):
            info(f"Updating Host {hostname}")
            host_overrides = overrides.copy()
            host_overrides['index'] = index
            for entry in host_param_overrides:
                if entry.get('mac', '') == hostname or entry.get('id', '') == hostname or\
                   entry.get('name', '') == hostname:
                    host_overrides.update(entry)
                    break
            self.update_host(hostname, host_overrides)

    def update_host(self, hostname, overrides):
        infra_envs = {}
        if 'infraenv' in overrides:
            infra_env = overrides['infraenv']
            infra_env_id = self.get_infra_env_id(infra_env)
            hosts = self.client.v2_list_hosts(infra_env_id=infra_env_id)
            matchingids = [host['id'] for host in hosts
                           if host['requested_hostname'].startswith(hostname) or host['id'].startswith(hostname) or
                           match_mac(host, hostname)]
            if matchingids:
                infra_envs[infra_env_id] = matchingids
        else:
            for infra_env in self.client.list_infra_envs():
                infra_env_id = infra_env['id']
                hosts = self.client.v2_list_hosts(infra_env_id=infra_env_id)
                matchingids = [host['id'] for host in hosts
                               if host['requested_hostname'].startswith(hostname) or host['id'].startswith(hostname) or
                               match_mac(host, hostname)]
                if matchingids:
                    infra_envs[infra_env_id] = matchingids
        if not infra_envs:
            error(f"No Matching Host with name {hostname} found")
        for infra_env_id in infra_envs:
            host_ids = infra_envs[infra_env_id]
            for index, host_id in enumerate(host_ids):
                role = None
                bind_updated = False
                extra_args_updated = False
                ignition_updated = False
                host_update_params = {}
                if 'cluster' in overrides:
                    cluster = overrides['cluster']
                    if cluster is None or cluster == '':
                        self.client.unbind_host(infra_env_id=infra_env_id, host_id=host_id)
                    else:
                        cluster_id = self.get_cluster_id(cluster)
                        bind_host_params = {'cluster_id': cluster_id}
                        bind_host_params = models.BindHostParams(**bind_host_params)
                        self.client.bind_host(infra_env_id, host_id, bind_host_params)
                    bind_updated = True
                if 'role' in overrides:
                    role = overrides['role']
                    host_update_params['host_role'] = role
                if 'name' in overrides or 'requested_hostname' in overrides:
                    newname = overrides.get('name', overrides.get('requested_hostname'))
                    if len(host_ids) > 1:
                        newname = f"{newname}-{index}"
                    host_update_params['host_name'] = newname
                if 'ignition_file' in overrides:
                    ignition_path = overrides['ignition_file']
                    if not os.path.exists(ignition_path):
                        warning(f"Ignition File {ignition_path} not found. Ignoring")
                    else:
                        ignition_data = open(ignition_path).read()
                        host_ignition_params = models.HostIgnitionParams(config=ignition_data)
                        self.client.v2_update_host_ignition(infra_env_id, host_id, host_ignition_params)
                        ignition_updated = True
                if 'relocate' in overrides and overrides['relocate'] and 'extra_args' not in overrides:
                    baremetal_cidr = overrides.get('baremetal_cidr', '192.168.7.0/24')
                    network = ip_network(baremetal_cidr)
                    mask = network.prefixlen
                    count = overrides.get('index')
                    ip_count = str(network[10 + count]) if count is not None else None
                    ip = overrides.get('ip') or ip_count
                    if ip is None:
                        warning("Cant set extra_args needed for relocation. Set ip")
                    else:
                        warning(f"Setting relocation ip of {host_id} to {ip}")
                        overrides['extra_args'] = f'--append-karg relocateip={ip} --append-karg relocatenetmask={mask}'
                if 'extra_args' in overrides:
                    extra_args = overrides['extra_args'].replace('-karg ', '-karg=')
                    extra_args = sum([entry.split('=', 1) for entry in extra_args.split(" ")], [])
                    installer_args_params = models.InstallerArgsParams(args=extra_args)
                    self.client.v2_update_host_installer_args(infra_env_id, host_id, installer_args_params)
                    extra_args_updated = True
                if 'mcp' in overrides:
                    valid_status = ["discovering", "known", "disconnected", "insufficient", "pending-for-input"]
                    currenthost = self.client.v2_get_host(infra_env_id=infra_env_id, host_id=host_id)
                    currentstatus = currenthost.status
                    if currentstatus not in valid_status:
                        error(f"Mcp can't be set for host {hostname} because of incorrect status {currentstatus}")
                    else:
                        mcp = overrides['mcp']
                        host_update_params['machine_config_pool_name'] = mcp
                if 'disk' in overrides or 'installation_disk_path' in overrides:
                    disk = overrides.get('installation_disk_path') or overrides.get('disk')
                    disk = os.path.basename(disk)
                    disk = f"/dev/{disk}"
                    host_update_params['disks_selected_config'] = [{"id": disk, "role": "install"}]
                if 'disks_skip_formatting' in overrides:
                    host_update_params['disks_skip_formatting'] = overrides['disks_skip_formatting']
                elif 'skip_disks' in overrides:
                    hostinfo = json.loads(self.client.v2_get_host(infra_env_id=infra_env_id, host_id=host_id).inventory)
                    disks = {disk['name']: disk['id'] for disk in hostinfo['disks']}
                    host_update_params['disks_skip_formatting'] = []
                    for entry in overrides['skip_disks']:
                        disk = os.path.basename(entry)
                        if disk in disks:
                            disk_id = disks[disk]
                        else:
                            continue
                        host_update_params['disks_skip_formatting'].append({"disk_id": disk_id,
                                                                            "skip_formatting": True})
                if 'node_labels' in overrides:
                    host_update_params['node_labels'] = overrides['node_labels']
                elif 'labels' in overrides:
                    node_labels = []
                    for label in overrides['labels']:
                        if isinstance(label, str):
                            key, value = tuple(label.split('=')) if '=' in label else (label, '')
                            node_labels.append({"key": key, "value": value})
                        elif isinstance(label, dict) and len(label) == 1:
                            key, value = list(label.keys())[0], str(list(label.values())[0])
                            node_labels.append({"key": key, "value": value})
                    host_update_params['node_labels'] = node_labels
                if host_update_params:
                    info(f"Updating host with id {host_id}")
                    host_update_params = models.HostUpdateParams(**host_update_params)
                    self.client.v2_update_host(infra_env_id=infra_env_id, host_id=host_id,
                                               host_update_params=host_update_params)
                elif not bind_updated and not extra_args_updated and not ignition_updated:
                    warning("Nothing updated for this host")

    def wait_hosts(self, name, number=3, filter_installed=False, require_inventory=False):
        client = self.client
        self.refresh_token(self.token, self.offlinetoken)
        infra_env_id = self.get_infra_env_id(name)
        infra_env = client.get_infra_env(infra_env_id=infra_env_id)
        cluster_id = infra_env.cluster_id
        if cluster_id is not None and client.v2_get_cluster(cluster_id=cluster_id).high_availability_mode == 'None':
            number = 1
        info(f"Waiting for hosts to reach expected number {number}", quiet=self.quiet)
        while True:
            try:
                current_hosts = client.v2_list_hosts(infra_env_id=infra_env_id)
                if require_inventory:
                    current_hosts = [h for h in current_hosts if 'inventory' in h]
                if filter_installed:
                    current_hosts = [h for h in current_hosts if h['status'] != 'installed']
                if len(current_hosts) >= number:
                    return
                else:
                    sleep(5)
                    self.refresh_token(self.token, self.offlinetoken)
            except KeyboardInterrupt:
                info("Leaving as per your request")
                sys.exit(0)

    def wait_cluster(self, name, status='installed'):
        cluster_id = self.get_cluster_id(name)
        info(f"Waiting for cluster {name} to reach state {status}", quiet=self.quiet)
        while True:
            try:
                cluster_info = self.client.v2_get_cluster(cluster_id=cluster_id).to_dict()
                if status == 'ready':
                    reached = cluster_info['status'] == 'ready'
                else:
                    reached = str(cluster_info['install_completed_at']) != '0001-01-01 00:00:00+00:00'
                if reached:
                    return
                else:
                    sleep(5)
                    self.refresh_token(self.token, self.offlinetoken)
            except KeyboardInterrupt:
                info("Leaving as per your request")
                sys.exit(0)

    def update_cluster(self, name, overrides):
        cluster_id = self.get_cluster_id(name)
        info_cluster = self.info_cluster(name)
        api_vip = overrides.get('api_vip') or overrides.get('api_ip')
        if 'api_vip' in overrides:
            del overrides['api_vip']
        if 'api_ip' in overrides:
            del overrides['api_ip']
        if api_vip is not None:
            api_vips = [x.ip for x in info_cluster.api_vips]
            if api_vip not in api_vips:
                overrides['api_vips'] = [{'ip': ip for ip in api_vips + [api_vip]}]
            else:
                api_vip = None
        ingress_vip = overrides.get('ingress_vip') or overrides.get('ingress_ip')
        if 'ingress_vip' in overrides:
            del overrides['ingress_vip']
        if 'ingress_ip' in overrides:
            del overrides['ingress_ip']
        if ingress_vip is not None:
            ingress_vips = [x.ip for x in info_cluster.ingress_vips]
            if ingress_vip not in ingress_vips:
                overrides['ingress_vips'] = [{'ip': ip for ip in ingress_vips + [ingress_vip]}]
            else:
                ingress_vip = None
        api_vips = overrides.get('api_vips', [])
        ingress_vips = overrides.get('ingress_vips', [])
        if (api_vips and not ingress_vips) or (ingress_vips and not api_vips):
            error("It's mandatory to define both api and ingress ips")
            sys.exit(1)
        if 'pull_secret' in overrides:
            pull_secret = os.path.expanduser(overrides['pull_secret'])
            if os.path.exists(pull_secret):
                overrides['pull_secret'] = re.sub(r"\s", "", open(pull_secret).read())
        if 'role' in overrides:
            role = overrides['role']
            hosts_roles = [{"id": host['id'], "role": role} for host in self.client.list_hosts(cluster_id=cluster_id)]
            overrides['hosts_roles'] = hosts_roles
        installconfig = {}
        if 'network_type' in overrides:
            installconfig['networking'] = {'networkType': overrides['network_type']}
            del overrides['network_type']
        if 'sno_disk' in overrides:
            sno_disk = overrides['sno_disk']
            if '/dev' not in sno_disk:
                sno_disk = f'/dev/{sno_disk}'
            installconfig['BootstrapInPlace'] = {'InstallationDisk': sno_disk}
        if 'tpm' in overrides and overrides['tpm']:
            if overrides.get('tpm_ctlplanes', False):
                enable_on = 'masters'
            elif overrides.get('tpm_workers', False):
                enable_on = 'masters'
            else:
                enable_on = 'all'
            installconfig['disk_encryption'] = {"enable_on": enable_on, "mode": "tpmv2"}
        if 'tang_servers' in overrides and isinstance(overrides['tang_servers'], list):
            if overrides.get('tpm_ctlplanes', False):
                enable_on = 'masters'
            elif overrides.get('tpm_workers', False):
                enable_on = 'masters'
            else:
                enable_on = 'all'
            tang_servers = overrides['tang_servers']
            installconfig['disk_encryption'] = {"enable_on": "all", "mode": "tpmv2", "tang_servers": tang_servers}
        if 'proxy' in overrides:
            proxy = overrides['proxy']
            if isinstance(proxy, str):
                httpProxy, httpsProxy = proxy, proxy
                noproxy = overrides.get('noproxy')
            elif isinstance(proxy, dict):
                httpProxy = proxy.get('http_proxy') or proxy.get('httpProxy')
                httpsProxy = proxy.get('https_proxy') or proxy.get('httpsProxy')
                noproxy = proxy.get('no_proxy') or proxy.get('noProxy')
            else:
                error(f"Invalid entry for proxy: {proxy}")
                sys.exit(1)
            if not httpProxy.startswith('http'):
                httpProxy = f'http://{httpProxy}'
            if not httpsProxy.startswith('http'):
                httpsProxy = f'http://{httpsProxy}'
            installconfig['proxy'] = {'httpProxy': httpProxy, 'httpsProxy': httpsProxy, 'noProxy': noproxy}
        if 'fips' in overrides and isinstance(overrides['fips'], bool):
            installconfig['fips'] = overrides['fips']
        if 'tags' in overrides:
            if isinstance(overrides['tags'], list):
                overrides['tags'] = ','.join(sorted(overrides['tags']))
        if 'installconfig' in overrides and isinstance(overrides['installconfig'], dict):
            installconfig.update(overrides['installconfig'])
            del overrides['installconfig']
        install_config_overrides = json.loads(info_cluster.install_config_overrides or '{}')
        if installconfig and install_config_overrides != installconfig:
            self.client.v2_update_cluster_install_config(cluster_id, json.dumps(installconfig))
        if 'olm_operators' in overrides:
            overrides['olm_operators'] = self.set_olm_operators(overrides['olm_operators'])
        if 'machine_networks' in overrides:
            overrides['machine_networks'] = self.set_machine_networks(cluster_id, overrides['machine_networks'])
        if 'service_networks' in overrides:
            overrides['service_networks'] = self.set_service_networks(cluster_id, overrides['service_networks'])
        if 'cluster_networks' in overrides:
            overrides['cluster_networks'] = self.set_cluster_networks(cluster_id, overrides['cluster_networks'])
        if 'platform' in overrides and isinstance(overrides['platform'], str):
            platform = overrides['platform']
            valid_platforms = ['baremetal', 'nutanix', 'vsphere', 'none', 'oci']
            if platform not in valid_platforms:
                error(f"Invalid platform. Should belong in {valid_platforms}")
                sys.exit(1)
            platform = {"type": platform}
            overrides['platform'] = platform
        if overrides:
            cluster_update_params = overrides.copy()
            allowed_parameters = self._allowed_parameters(models.V2ClusterUpdateParams)
            for parameter in overrides:
                if parameter not in allowed_parameters:
                    del cluster_update_params[parameter]
            if cluster_update_params:
                cluster_update_params = models.V2ClusterUpdateParams(**cluster_update_params)
                self.client.v2_update_cluster(cluster_id=cluster_id, cluster_update_params=cluster_update_params)
        if 'mtu' in overrides:
            mtu = overrides['mtu']
            mtu_manifest = {'apiVersion': 'operator.openshift.io/v1', 'kind': 'Network',
                            'metadata': {'name': 'cluster'}, 'spec': {'defaultNetwork':
                                                                      {'type': 'OVNKubernetes', 'ovnKubernetesConfig':
                                                                       {'mtu': mtu}}}}
            mtu_manifest = {'99-ovn.yaml': yaml.dump(mtu_manifest)}
            self.upload_manifests(name, directory=[mtu_manifest], openshift=True)
        if 'manifests' in overrides:
            self.upload_manifests(name, directory=overrides['manifests'], openshift=False)
        if 'openshift_manifests' in overrides:
            self.upload_manifests(name, directory=overrides['openshift_manifests'], openshift=True)
        if 'ignore_validations' in overrides and overrides['ignore_validations']:
            ignored_validations = models.IgnoredValidations(cluster_validation_ids='all')
            self.client.v2_set_ignored_validations(cluster_id=cluster_id, ignored_validations=ignored_validations)
        if 'day2' in overrides and isinstance(overrides['day2'], bool) and overrides['day2']\
           and info_cluster.status == "installed":
            info(f"Converting cluster {name} to day2")
            self.client.transform_cluster_to_day2(cluster_id)

    def start_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        cluster_info = self.client.v2_get_cluster(cluster_id=cluster_id).to_dict()
        if cluster_info['status'] == 'adding-hosts':
            infra_env_id = self.get_infra_env_id(name)
            for host in self.client.v2_list_hosts(infra_env_id=infra_env_id):
                if host['status'] in ['installed', 'added-to-existing-cluster']:
                    info(f"Skipping installed Host {host['requested_hostname']}")
                else:
                    info(f"Installing Host {host['requested_hostname']}")
                    host_id = host['id']
                    self.client.v2_install_host(infra_env_id=infra_env_id, host_id=host_id)
        else:
            self.client.v2_install_cluster(cluster_id=cluster_id)

    def start_hosts(self, hostnames=[]):
        for infra_env in self.client.list_infra_envs():
            infra_env_id = infra_env['id']
            infra_env_hosts = self.client.v2_list_hosts(infra_env_id=infra_env_id)
            hosts = [h for h in infra_env_hosts if h['requested_hostname'] in hostnames or h['id'] in hostnames]
            if hosts:
                host = hosts[0]
                if host['status'] in ['installed', 'added-to-existing-cluster']:
                    info(f"Skipping installed Host {host['requested_hostname']}")
                else:
                    info(f"Installing Host {host['requested_hostname']}")
                    host_id = host['id']
                    self.client.v2_install_host(infra_env_id=infra_env_id, host_id=host_id)

    def stop_hosts(self, hostnames=[]):
        for infra_env in self.client.list_infra_envs():
            infra_env_id = infra_env['id']
            infra_env_hosts = self.client.v2_list_hosts(infra_env_id=infra_env_id)
            hosts = [h for h in infra_env_hosts if h['requested_hostname'] in hostnames or h['id'] in hostnames]
            if hosts:
                host = hosts[0]
                if host['status'] != "adding-hosts":
                    info(f"Skipping Host {host['requested_hostname']}")
                else:
                    info(f"Resetting Host {host['requested_hostname']}")
                    host_id = host['id']
                    self.client.v2_reset_host(infra_env_id=infra_env_id, host_id=host_id)

    def stop_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        self.client.v2_reset_cluster(cluster_id=cluster_id)

    def upload_manifests(self, name, directory, openshift=False):
        cluster_id = self.get_cluster_id(name)
        cleanup = False
        if isinstance(directory, list):
            cleanup = True
            tmpdir = TemporaryDirectory()
            for manifest in directory:
                _fic, content = list(manifest.keys())[0], list(manifest.values())[0]
                if not _fic.endswith('.yml') and not _fic.endswith('.yaml'):
                    warning(f"Skipping file {_fic}")
                    continue
                with open(f'{tmpdir.name}/{_fic}', 'w') as f:
                    f.write(content)
            directory = tmpdir.name
        if not os.path.exists(directory):
            error(f"Directory {directory} not found")
            sys.exit(1)
        elif not os.path.isdir(directory):
            error(f"{directory} is not a directory")
            sys.exit(1)
        manifests_api = api.ManifestsApi(api_client=self.api)
        _fics = os.listdir(directory)
        if not _fics:
            error(f"No files found in directory {directory}")
            sys.exit(0)
        for _fic in _fics:
            if not _fic.endswith('.yml') and not _fic.endswith('.yaml'):
                warning(f"Skipping file {_fic}")
                continue
            info(f"Uploading file {_fic}")
            content = base64.b64encode(open(f"{directory}/{_fic}").read().encode()).decode("UTF-8")
            folder = 'manifests' if not openshift else 'openshift'
            manifest_info = {'file_name': _fic, 'content': content, 'folder': folder}
            create_manifest_params = models.CreateManifestParams(**manifest_info)
            manifests_api.v2_create_cluster_manifest(cluster_id, create_manifest_params)
        if cleanup:
            tmpdir.cleanup()

    def delete_manifests(self, name, directory, manifests=[]):
        cluster_id = self.get_cluster_id(name)
        manifests_api = api.ManifestsApi(api_client=self.api)
        all_manifests = [m['file_name'] for m in manifests_api.v2_list_cluster_manifests(cluster_id)]
        if not manifests and directory is None:
            manifests = all_manifests
        if manifests:
            for manifest in manifests:
                if manifest in all_manifests:
                    info(f"Deleting file {manifest}")
                    manifests_api.v2_delete_cluster_manifest(cluster_id, manifest)
            sys.exit(0)
        elif not os.path.exists(directory):
            error(f"Directory {directory} not found")
            sys.exit(1)
        elif not os.path.isdir(directory):
            error(f"{directory} is not a directory")
            sys.exit(1)
        _fics = os.listdir(directory)
        if not _fics:
            error(f"No files found in directory {directory}")
            sys.exit(0)
        for _fic in _fics:
            if _fic in all_manifests:
                info(f"Deleting file {_fic}")
                manifests_api.v2_delete_cluster_manifest(cluster_id, _fic)

    def list_manifests(self, name):
        results = []
        cluster_id = self.get_cluster_id(name)
        manifests_api = api.ManifestsApi(api_client=self.api)
        manifests = manifests_api.v2_list_cluster_manifests(cluster_id)
        for manifest in manifests:
            results.append({'file_name': manifest['file_name'], 'folder': manifest['folder']})
        return results

    def download_manifests(self, name, path='.'):
        cluster_id = self.get_cluster_id(name)
        manifests_api = api.ManifestsApi(api_client=self.api)
        manifests = manifests_api.v2_list_cluster_manifests(cluster_id)
        for manifest in manifests:
            folder = manifest['folder']
            file_name = manifest['file_name']
            info(f"Downloading {file_name}")
            response = manifests_api.v2_download_cluster_manifest(cluster_id, file_name, folder=folder,
                                                                  _preload_content=False)
            file_path = f"{path}/{file_name}"
            with open(file_path, "wb") as f:
                copyfileobj(response, f)

    def update_installconfig(self, name, overrides={}):
        cluster_id = self.get_cluster_id(name)
        installconfig = {}
        if 'network_type' in overrides or 'sno_disk' in overrides:
            if 'network_type' in overrides:
                installconfig['networking'] = {'networkType': overrides['network_type']}
            if 'sno_disk' in overrides:
                sno_disk = overrides['sno_disk']
                if '/dev' not in sno_disk:
                    sno_disk = f'/dev/{sno_disk}'
                installconfig['BootstrapInPlace'] = {'InstallationDisk': sno_disk}
        else:
            installconfig = overrides.get('installconfig')
            if installconfig is None:
                warning("installconfig is not set. Using provided parameters to craft install config")
                installconfig = overrides
            if not isinstance(installconfig, dict):
                error("installconfig is not in correct format")
                sys.exit(1)
        self.client.v2_update_cluster_install_config(cluster_id, json.dumps(installconfig))

    def update_iso(self, name, overrides={}):
        iso_overrides = overrides.copy()
        infra_env_id = self.get_infra_env_id(name)
        if 'ignition_config_override' not in iso_overrides:
            ignition_config_override = self.set_disconnected_ignition_config_override(infra_env_id, iso_overrides)
            if ignition_config_override is not None:
                iso_overrides['ignition_config_override'] = ignition_config_override
        self.update_infra_env(name, overrides=iso_overrides)

    def info_service(self):
        print(f"url: {self.url}")
        versionapi = api.VersionsApi(api_client=self.api)
        component_versions = versionapi.v2_list_component_versions().to_dict()
        print(f"release: {component_versions['release_tag']}")
        supported_versions = versionapi.v2_list_supported_openshift_versions()
        print("supported openshift versions:")
        for version in supported_versions:
            print(version)
        operatorsapi = api.OperatorsApi(api_client=self.api)
        supported_operators = operatorsapi.v2_list_supported_operators()
        print("supported operators:")
        for operator in sorted(supported_operators):
            print(operator)

    def get_infra_env_id(self, name):
        valid_names = [name, f'{name}_infra-env']
        matching_ids = [x['id'] for x in self.list_infra_envs() if x['name'] in valid_names or x['id'] == name]
        if matching_ids:
            return matching_ids[0]
        else:
            error(f"Infraenv {name} not found")
            sys.exit(1)

    def get_infra_env_name(self, _id):
        matching_names = [x['name'] for x in self.list_infra_envs() if x['id'] == _id]
        if matching_names:
            return matching_names[0]
        else:
            error(f"Infraenv {_id} not found")
            sys.exit(1)

    def create_infra_env(self, name, overrides={}, quiet=True):
        existing_ids = [x['id'] for x in self.list_infra_envs() if x['name'] == name]
        if existing_ids:
            error(f"Infraenv {name} already there. Leaving")
            sys.exit(1)
        self.set_default_values(overrides, quiet=quiet)
        self.set_default_infraenv_values(overrides)
        new_infraenv_params = default_infraenv_params
        new_infraenv_params['name'] = name
        cluster = overrides.get('cluster_id') or overrides.get('cluster')
        if cluster is not None:
            overrides['cluster_id'] = self.get_cluster_id(cluster)
        allowed_parameters = self._allowed_parameters(models.InfraEnvCreateParams)
        for parameter in overrides:
            if parameter in allowed_parameters:
                new_infraenv_params[parameter] = overrides[parameter]
        infraenv_create_params = models.InfraEnvCreateParams(**new_infraenv_params)
        self.client.register_infra_env(infraenv_create_params=infraenv_create_params)

    def delete_infra_env(self, name):
        infra_env_id = self.get_infra_env_id(name)
        self.client.deregister_infra_env(infra_env_id=infra_env_id)
        day2_matching_ids = [x['id'] for x in self.list_infra_envs() if x['name'] == f'{name}-day2']
        if day2_matching_ids:
            self.client.deregister_infra_env(infra_env_id=day2_matching_ids[0])

    def info_infra_env(self, name):
        infra_env_id = self.get_infra_env_id(name)
        return self.client.get_infra_env(infra_env_id=infra_env_id)

    def list_infra_envs(self):
        return self.client.list_infra_envs()

    def update_infra_env(self, name, overrides={}):
        infra_env_update_params = {}
        infra_env_id = self.get_infra_env_id(name)
        self.set_default_values(overrides, existing=True)
        self.set_default_infraenv_values(overrides)
        infra_env_update_params = {}
        allowed_parameters = self._allowed_parameters(models.InfraEnvUpdateParams)
        for parameter in overrides:
            if parameter == 'pull_secret' and os.path.exists(os.path.expanduser(overrides['pull_secret'])):
                pull_secret = os.path.expanduser(overrides['pull_secret'])
                infra_env_update_params[parameter] = re.sub(r"\s", "", open(pull_secret).read())
            elif parameter in allowed_parameters:
                infra_env_update_params[parameter] = overrides[parameter]
        if infra_env_update_params:
            infra_env_update_params = models.InfraEnvUpdateParams(**infra_env_update_params)
            self.client.update_infra_env(infra_env_id=infra_env_id, infra_env_update_params=infra_env_update_params)

    def bind_infra_env(self, name, cluster, force=False):
        infra_env_id = self.get_infra_env_id(name)
        cluster_id = self.get_cluster_id(cluster)
        for host in self.client.v2_list_hosts(infra_env_id=infra_env_id):
            host_id = host['id']
            host_name = host['requested_hostname']
            host_cluster_id = host.get('cluster_id')
            if host_cluster_id is not None:
                if host_cluster_id == cluster_id:
                    info(f"Host {host_name} already bound to Cluster {cluster}")
                    continue
                elif not force:
                    info(f"Host {host_name} already bound another cluster")
                    continue
                else:
                    host_cluster = self.get_cluster_name(host_cluster_id)
                    info(f"Unbinding Host {host_name} from Cluster {host_cluster}")
                    self.client.unbind_host(infra_env_id=infra_env_id, host_id=host_id)
                    while True:
                        currenthost = self.client.v2_get_host(infra_env_id=infra_env_id, host_id=host_id)
                        currentstatus = currenthost.status
                        if currentstatus == 'known-unbound':
                            break
                        else:
                            info(f"Waiting 5s for host {host_name} to get unbound", quiet=self.quiet)
                            sleep(5)
            info(f"Binding Host {host_name} to Cluster {cluster}")
            bind_host_params = {'cluster_id': cluster_id}
            bind_host_params = models.BindHostParams(**bind_host_params)
            self.client.bind_host(infra_env_id, host_id, bind_host_params)

    def start_infraenv(self, name):
        infra_env_id = self.get_infra_env_id(name)
        for host in self.client.v2_list_hosts(infra_env_id=infra_env_id):
            if host['status'] in ['installed', 'added-to-existing-cluster']:
                info(f"Skipping installed host {host['requested_hostname']}")
            elif 'cluster_id' not in host:
                info(f"Skipping unassigned host {host['requested_hostname']}")
            else:
                info(f"Installing Host {host['requested_hostname']}")
                host_id = host['id']
                self.client.v2_install_host(infra_env_id=infra_env_id, host_id=host_id)

    def stop_infraenv(self, name):
        infra_env_id = self.get_infra_env_id(name)
        for host in self.client.v2_list_hosts(infra_env_id=infra_env_id):
            if host['status'] == 'installed':
                info(f"Skipping Host {host['requested_hostname']}")
            else:
                host_id = host['id']
                self.client.v2_reset_host(infra_env_id=infra_env_id, host_id=host_id)

    def unbind_infra_env(self, name):
        infra_env_id = self.get_infra_env_id(name)
        for host in self.client.v2_list_hosts(infra_env_id=infra_env_id):
            host_id = host['id']
            host_cluster_id = host.get('cluster_id')
            host_name = host['requested_hostname']
            if host_cluster_id is None:
                info(f"Host {host_name} already unbound")
                continue
            info(f"Unbinding Host {host_name}")
            self.client.unbind_host(infra_env_id=infra_env_id, host_id=host_id)

    def list_events(self, name):
        cluster_id = self.get_cluster_id(name)
        events_api = api.EventsApi(api_client=self.api)
        events = events_api.v2_list_events(cluster_id=cluster_id)
        return events

    def get_extra_keywords(self):
        return ['sno', 'pull_secret', 'domain', 'tpm', 'minimal', 'static_network_config', 'proxy', 'disconnected_url',
                'disconnected_ca', 'network_type', 'sno_disk', 'tpm_ctlplanes', 'tpm_workers', 'tang_servers', 'api_ip',
                'ingress_ip', 'role', 'manifests', 'openshift_manifests', 'disk', 'mcp', 'extra_args', 'ignition_file',
                'discovery_ignition_file', 'hosts', 'registry_url', 'fips', 'skip_disks', 'labels', 'relocate',
                'relocate_switch', 'relocate_registry', 'relocate_cidr', 'download_iso_path', 'ignore_validations',
                'mtu', 'platform']

    def create_deployment(self, cluster, overrides, force=False, debug=False):
        self.create_cluster(cluster, overrides.copy(), force=force)
        infraenv = f"{cluster}_infra-env"
        minimal = overrides.get('minimal', False)
        overrides['cluster'] = cluster
        self.create_infra_env(infraenv, overrides)
        del overrides['cluster']
        if not self.saas:
            info("Waiting 240s for iso to be available")
            sleep(240)
        if 'iso_url' in overrides:
            download_iso_path = overrides.get('download_iso_path')
            if download_iso_path is None:
                download_iso_path = '/var/www/html'
                warning(f"Using {download_iso_path} to store iso")
            else:
                info(f"Using {download_iso_path} to store iso")
            self.download_iso(cluster, download_iso_path)
        else:
            iso_url = self.info_iso(infraenv, overrides, minimal=minimal)
            if 'hosts' not in overrides:
                warning(f"Retrieve iso from {iso_url} and plug it to your nodes:")
            else:
                overrides['iso_url'] = iso_url
        download_iso_cmd = overrides.get('download_iso_cmd')
        if download_iso_cmd is not None:
            call(download_iso_cmd, shell=True)
        if 'hosts' in overrides:
            boot_overrides = overrides.copy()
            boot_overrides['cluster'] = cluster
            boot_result = boot_hosts(boot_overrides, debug=debug)
            if boot_result != 0:
                return {'result': 'failure', 'reason': 'Hit issue when booting hosts'}
        if 'hosts_number' in overrides:
            hosts_number = overrides.get('hosts_number')
        elif 'hosts' in overrides and isinstance(overrides['hosts'], list):
            hosts_number = len(overrides.get('hosts'))
        elif 'sno' in overrides and overrides['sno']:
            hosts_number = 1
        else:
            hosts_number = 3
        info(f"Setting hosts_number to {hosts_number}")
        self.wait_hosts(infraenv, hosts_number, filter_installed=True, require_inventory=True)
        if 'hosts' in overrides:
            self.update_hosts([], overrides)
        self.update_cluster(cluster, overrides)
        self.wait_cluster(cluster, 'ready')
        self.start_cluster(cluster)
        self.wait_cluster(cluster)
        info(f"Downloading Kubeconfig for Cluster {cluster} in current directory")
        self.download_kubeconfig(cluster, '.')
        return {'result': 'success'}

    def create_fake_host(self, name, cluster, secret_key, overrides={}):
        infra_env_id = self.get_infra_env_id(cluster)
        agent_version = 'registry.redhat.io/rhai-tech-preview/assisted-installer-agent-rhel8:v1.0.0-248'
        host_id = str(uuid1())
        info(f"Using uuid {host_id}")
        new_host_params = {"host_id": host_id, "discovery_agent_version": agent_version}
        new_host_params = models.HostCreateParams(**new_host_params)
        self.client.api_client.default_headers['X-Secret-Key'] = secret_key
        self.client.v2_register_host(infra_env_id=infra_env_id, new_host_params=new_host_params)

    def scale_deployment(self, cluster, overrides, force=False, debug=False):
        if cluster.endswith('-day2'):
            self.create_cluster(cluster, overrides.copy(), force=force)
            infraenv = f"{cluster}_infra-env"
            minimal = overrides.get('minimal', False)
            overrides['cluster'] = cluster
            self.create_infra_env(infraenv, overrides)
            del overrides['cluster']
        else:
            info_cluster = self.info_cluster(cluster)
            if info_cluster.status != 'adding-hosts':
                self.update_cluster(cluster, {'day2': True})
        if not self.saas:
            info("Waiting 240s for iso to be available")
            sleep(240)
        if 'iso_url' in overrides:
            download_iso_path = overrides.get('download_iso_path')
            if download_iso_path is None:
                download_iso_path = '/var/www/html'
                warning(f"Using {download_iso_path} to store iso")
            else:
                info(f"Using {download_iso_path} to store iso")
            self.download_iso(cluster, download_iso_path)
        else:
            iso_url = self.info_iso(infraenv, overrides, minimal=minimal)
            if 'hosts' not in overrides:
                warning(f"Retrieve iso from {iso_url} and plug it to your nodes:")
            else:
                overrides['iso_url'] = iso_url
        download_iso_cmd = overrides.get('download_iso_cmd')
        if download_iso_cmd is not None:
            call(download_iso_cmd, shell=True)
        hosts_number = len(overrides.get('hosts', [0, 0]))
        info(f"Setting hosts_number to {hosts_number}")
        if 'hosts' not in overrides:
            boot_overrides = overrides.copy()
            boot_overrides['cluster'] = cluster
            boot_result = boot_hosts(boot_overrides, debug=debug)
            if boot_result != 0:
                return {'result': 'failure', 'reason': 'Hit issue when booting hosts'}
        self.wait_hosts(infraenv, hosts_number, filter_installed=True, require_inventory=True)
        hosts = [h['requested_hostname'] for h in self.list_hosts() if h['status'] != 'installed']
        self.start_hosts(hosts)
        return {'result': 'success'}
