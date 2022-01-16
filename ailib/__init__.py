from assisted_service_client import ApiClient, Configuration, api, models
from ailib.common import warning, error, info, get_token
import base64
from datetime import datetime
from ipaddress import ip_network
import json
import os
import re
import socket
import sys
from time import sleep
import yaml
import urllib
from urllib.request import urlretrieve
from shutil import copyfileobj


# default_cluster_params = {"openshift_version": "4.6", "base_dns_domain": "karmalabs.com",
#                          "cluster_network_cidr": "string", "cluster_network_host_prefix": 24,
#                          "service_network_cidr": "string", "vip_dhcp_allocation": False}
default_cluster_params = {"openshift_version": "4.9", "base_dns_domain": "karmalabs.com", "vip_dhcp_allocation": False}
default_infraenv_params = {"openshift_version": "4.9", "image_type": "full-iso"}


class AssistedClient(object):
    def __init__(self, url, token=None, offlinetoken=None):
        self.url = url
        config = Configuration()
        config.host = self.url + "/api/assisted-install"
        config.verify_ssl = False
        proxies = urllib.request.getproxies()
        if proxies:
            proxy = proxies.get('https') or proxies.get('http')
            if 'http' not in proxy:
                proxy = "http://" + proxy
                warning(f"Detected proxy env var without scheme, updating proxy to {proxy}")
            config.proxy = proxy
        aihome = f"{os.environ['HOME']}/.aicli"
        if not os.path.exists(aihome):
            os.mkdir(aihome)
        if url in ['https://api.openshift.com', 'https://api.stage.openshift.com']:
            if offlinetoken is None:
                if os.path.exists(f'{aihome}/offlinetoken.txt'):
                    offlinetoken = open(f'{aihome}/offlinetoken.txt').read().strip()
                else:
                    error(f"offlinetoken needs to be set to gather token for {url}")
                    error("get it at https://cloud.redhat.com/openshift/token")
                    if os.path.exists('/i_am_a_container'):
                        error("use -e AI_OFFLINETOKEN=$AI_OFFLINETOKEN to expose it in container mode")
                    sys.exit(1)
            if not os.path.exists(f'{aihome}/offlinetoken.txt'):
                with open(f'{aihome}/offlinetoken.txt', 'w') as f:
                    f.write(offlinetoken)
            if os.path.exists(f'{aihome}/token.txt'):
                token = open(f'{aihome}/token.txt').read().strip()
            try:
                token = get_token(token=token, offlinetoken=offlinetoken)
            except Exception as e:
                error(f"Hit issue when trying to set token. Got {e}")
                if os.path.exists(f'{aihome}/offlinetoken.txt'):
                    error("Removing offlinetoken file")
                    os.remove(f'{aihome}/offlinetoken.txt')
                sys.exit(1)
            config.api_key['Authorization'] = token
            config.api_key_prefix['Authorization'] = 'Bearer'
        self.api = ApiClient(configuration=config)
        self.client = api.InstallerApi(api_client=self.api)

    def set_default_values(self, overrides):
        if 'openshift_version' in overrides and isinstance(overrides['openshift_version'], float):
            overrides['openshift_version'] = str(overrides['openshift_version'])
        if 'pull_secret' not in overrides:
            warning("Using openshift_pull.json as pull_secret file")
            overrides['pull_secret'] = "openshift_pull.json"
        pull_secret = os.path.expanduser(overrides['pull_secret'])
        if not os.path.exists(pull_secret):
            error(f"Missing pull secret file {pull_secret}")
            sys.exit(1)
        overrides['pull_secret'] = re.sub(r"\s", "", open(pull_secret).read())
        if 'ssh_public_key' not in overrides:
            pub_key = overrides.get('public_key', f"{os.environ['HOME']}/.ssh/id_rsa.pub")
            if os.path.exists(pub_key):
                overrides['ssh_public_key'] = open(pub_key).read().strip()
            else:
                error(f"Missing public key file {pub_key}")
                sys.exit(1)
            if 'public_key' in overrides:
                del overrides['public_key']
        if 'sno' in overrides:
            if overrides['sno']:
                overrides['high_availability_mode'] = "None"
                overrides['user_managed_networking'] = True
            del overrides['sno']
        if 'high_availability_mode' in overrides and overrides['high_availability_mode'] is None:
            overrides['high_availability_mode'] = "None"
        if 'olm_operators' in overrides:
            overrides['olm_operators'] = self.set_olm_operators(overrides['olm_operators'])
        if 'tpm' in overrides and overrides['tpm']:
            overrides['disk_encryption'] = {"enable_on": "all", "mode": "tpmv2"}
            del overrides['tpm']
        if 'tang_servers' in overrides:
            tang_servers = overrides['tang_servers']
            if isinstance(tang_servers, list):
                tang_servers = ','.join(tang_servers)
            overrides['disk_encryption'] = {"enable_on": "all", "mode": "tpmv2", "tang_servers": tang_servers}
            del overrides['tang_servers']

    def set_default_infraenv_values(self, overrides):
        if 'cluster' in overrides:
            cluster_id = self.get_cluster_id(overrides['cluster'])
            overrides['cluster_id'] = cluster_id
            del overrides['cluster']
        if 'minimal' in overrides:
            image_type = "minimal-iso" if overrides['minimal'] else 'full-iso'
            overrides['image_type'] = image_type
            del overrides['minimal']
        static_network_config = overrides.get('static_network_config', [])
        if static_network_config:
            if isinstance(static_network_config, dict):
                static_network_config = [static_network_config]
            final_network_config = []
            for entry in static_network_config:
                mac_interface_map = []
                for interface in entry['interfaces']:
                    if 'bond' not in interface['name']:
                        logical_nic_name, mac_address = interface['name'], interface['mac-address']
                        mac_interface_map.append({"mac_address": mac_address, "logical_nic_name": logical_nic_name})
                new_entry = {'network_yaml': yaml.dump(entry), 'mac_interface_map': mac_interface_map}
                final_network_config.append(models.HostStaticNetworkConfig(**new_entry))
            static_network_config = final_network_config
            overrides['static_network_config'] = static_network_config
        if 'ssh_authorized_key' not in overrides:
            pub_key = overrides.get('public_key', f"{os.environ['HOME']}/.ssh/id_rsa.pub")
            if os.path.exists(pub_key):
                overrides['ssh_authorized_key'] = open(pub_key).read().strip()
            else:
                error(f"Missing public key file {pub_key}")
                sys.exit(1)
            if 'public_key' in overrides:
                del overrides['public_key']
        if 'ignition_config_override' not in overrides:
            iso_overrides = overrides.copy()
            iso_overrides['ignition_version'] = '3.1.0'
            ignition_config_override = self.set_disconnected_ignition_config_override(infra_env_id=None,
                                                                                      overrides=iso_overrides)
            if ignition_config_override is not None:
                overrides['ignition_config_override'] = ignition_config_override

    def set_disconnected_ignition_config_override(self, infra_env_id=None, overrides={}):
        ignition_config_override = None
        disconnected_url = overrides.get('disconnected_url')
        ca = overrides.get('disconnected_ca')
        if ca is None:
            if 'installconfig' in overrides and isinstance(overrides['installconfig'], dict)\
                    and 'additionalTrustBundle' in overrides['installconfig']:
                info("using cert from installconfig/additionalTrustBundle")
                ca = overrides['installconfig']['additionalTrustBundle']
        if 'ignition_config_override' not in overrides and disconnected_url is not None and ca is not None:
            ignition_version = overrides.get('ignition_version')
            if ignition_version is None:
                ori = self.client.v2_download_infra_env_files(infra_env_id=infra_env_id, file_name="discovery.ign",
                                                              _preload_content=False)
                ignition_version = json.loads(ori.read().decode("utf-8"))['ignition']['version']
            ailibdir = os.path.dirname(warning.__code__.co_filename)
            with open(f"{ailibdir}/registries.conf.templ") as f:
                data = f.read()
                registries = data % {'url': disconnected_url}
            registries_encoded = base64.b64encode(registries.encode()).decode("UTF-8")
            ca_encoded = base64.b64encode(ca.encode()).decode("UTF-8")
            fil1 = {"path": "/etc/containers/registries.conf", "mode": 420, "overwrite": True,
                    "user": {"name": "root"},
                    "contents": {"source": f"data:text/plain;base64,{registries_encoded}"}}
            fil2 = {"path": "/etc/pki/ca-trust/source/anchors/domain.crt", "mode": 420, "overwrite": True,
                    "user": {"name": "root"}, "contents": {"source": f"data:text/plain;base64,{ca_encoded}"}}
            ignition_config_override = json.dumps({"ignition": {"version": ignition_version},
                                                   "storage": {"files": [fil1, fil2]}})
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
                if 'host_prefix' in cluster_network:
                    host_prefix = cluster_network['host_prefix']
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

    def create_cluster(self, name, overrides={}):
        allowed_parameters = ["name", "openshift_version", "base_dns_domain", "cluster_network_cidr",
                              "cluster_network_host_prefix", "service_network_cidr", "ingress_vip", "pull_secret",
                              "ssh_public_key", "vip_dhcp_allocation", "http_proxy", "https_proxy", "no_proxy",
                              "high_availability_mode", "user_managed_networking", "additional_ntp_source",
                              "olm_operators", "disk_encryption", "schedulable_masters", "hyperthreading",
                              "ocp_release_image"]
        existing_ids = [x['id'] for x in self.list_clusters() if x['name'] == name]
        if existing_ids:
            error(f"Cluster {name} already there. Leaving")
            sys.exit(1)
        if name.endswith('-day2'):
            self.create_day2_cluster(name, overrides)
            return
        self.set_default_values(overrides)
        new_cluster_params = default_cluster_params
        new_cluster_params['name'] = name
        for parameter in overrides:
            if parameter in allowed_parameters:
                new_cluster_params[parameter] = overrides[parameter]
        cluster_params = models.ClusterCreateParams(**new_cluster_params)
        self.client.v2_register_cluster(new_cluster_params=cluster_params)

    def delete_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
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
        allowed_parameters = ["name", "openshift_version", "base_dns_domain", "cluster_network_cidr",
                              "cluster_network_host_prefix", "service_network_cidr", "ingress_vip",
                              "ssh_public_key", "vip_dhcp_allocation", "http_proxy", "https_proxy", "no_proxy",
                              "high_availability_mode", "user_managed_networking", "additional_ntp_source",
                              "disk_encryption", "schedulable_masters", "hyperthreading",
                              "ocp_release_image", "api_vip", "ingress_vip"]
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
        cluster_name = name.replace('-day2', '')
        existing_ids = [x['id'] for x in self.list_clusters() if x['name'] == cluster_name]
        api_ip = None
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
            api_name = "api." + cluster_name + "." + domain
            self.set_default_values(overrides)
            pull_secret, ssh_public_key = overrides['pull_secret'], overrides['ssh_public_key']
        else:
            cluster_id = self.get_cluster_id(cluster_name)
            cluster = self.client.v2_get_cluster(cluster_id=cluster_id)
            openshift_version = cluster.openshift_version
            ssh_public_key = cluster.image_info.ssh_public_key
            api_name = "api." + cluster_name + "." + cluster.base_dns_domain
            api_ip = cluster.api_vip
            response = self.client.v2_download_cluster_files(cluster_id=cluster_id, file_name="install-config.yaml",
                                                             _preload_content=False)
            data = yaml.safe_load(response.read().decode("utf-8"))
            pull_secret = data.get('pullSecret')
        try:
            socket.gethostbyname(api_name)
        except:
            if api_ip is not None:
                warning(f"Forcing api_vip_dnsname to {api_ip}")
                api_name = api_ip
            else:
                warning(f"{api_name} doesn't resolve")
                warning(f"run aicli update cluster {name} -P api_vip_dnsname=$api_ip")
        new_import_cluster_params = {"name": name, "openshift_version": str(openshift_version),
                                     "api_vip_dnsname": api_name, 'openshift_cluster_id': cluster_id}
        new_import_cluster_params = models.ImportClusterParams(**new_import_cluster_params)
        self.client.v2_import_cluster(new_import_cluster_params=new_import_cluster_params)
        cluster_update_params = {'pull_secret': pull_secret, 'ssh_public_key': ssh_public_key}
        cluster_update_params = models.ClusterUpdateParams(**cluster_update_params)
        new_cluster_id = self.get_cluster_id(name)
        self.client.v2_update_cluster(cluster_id=new_cluster_id, cluster_update_params=cluster_update_params)

    def _expired_iso(self, iso_url):
        search = re.search(r".*&image_token=(.*)&type=.*", iso_url)
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
        if self._expired_iso(iso_url):
            iso_url = self.client.get_infra_env_download_url(infra_env['id']).url
        info(iso_url)

    def download_iso(self, name, path):
        infra_env = self.info_infra_env(name).to_dict()
        iso_url = infra_env['download_url']
        if self._expired_iso(iso_url):
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

    def download_installconfig(self, name, path):
        cluster_id = self.get_cluster_id(name)
        response = self.client.v2_download_cluster_files(cluster_id=cluster_id, file_name="install-config.yaml",
                                                         _preload_content=False)
        with open(f"{path}/install-config.yaml.{name}", "wb") as f:
            copyfileobj(response, f)

    def download_kubeadminpassword(self, name, path):
        cluster_id = self.get_cluster_id(name)
        response = self.client.v2_download_cluster_credentials(cluster_id=cluster_id, file_name="kubeadmin-password",
                                                               _preload_content=False)
        with open(f"{path}/kubeadmin-password.{name}", "wb") as f:
            copyfileobj(response, f)

    def download_kubeconfig(self, name, path):
        cluster_id = self.get_cluster_id(name)
        response = self.client.v2_download_cluster_credentials(cluster_id=cluster_id, file_name="kubeconfig-noingress",
                                                               _preload_content=False)
        with open(f"{path}/kubeconfig.{name}", "wb") as f:
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

    def update_host(self, hostname, overrides):
        infra_envs = {}
        if 'infraenv' in overrides:
            infra_env = overrides['infraenv']
            infra_env_id = self.get_infra_env_id(infra_env)
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
            for index, host_id in enumerate(host_ids):
                role = None
                bind_updated = False
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
                if 'ignition' in overrides:
                    ignition_path = overrides['ignition']
                    if not os.path.exists(ignition_path):
                        warning(f"Ignition {ignition_path} not found. Ignoring")
                    else:
                        ignition_data = open(ignition_path).read()
                        host_ignition_params = models.HostIgnitionParams(config=ignition_data)
                        self.client.v2_update_host_ignition(infra_env_id, host_id, host_ignition_params)
                if 'extra_args' in overrides and cluster_id is not None:
                    extra_args = overrides['extra_args']
                    installer_args_params = models.InstallerArgsParams(args=extra_args)
                    self.client.v2_update_host_installer_args(cluster_id, host_id, installer_args_params)
                if 'mcp' in overrides:
                    valid_status = ["discovering", "known", "disconnected", "insufficient", "pending-for-input"]
                    currenthost = self.client.v2_get_host(infra_env_id=infra_env_id, host_id=host_id)
                    currentstatus = currenthost.status
                    if currentstatus not in valid_status:
                        error(f"Mcp can't be set for host {hostname} because of incorrect status {currentstatus}")
                    else:
                        mcp = overrides['mcp']
                        host_update_params['machine_config_pool_name'] = mcp
                if host_update_params:
                    info(f"Updating host with id {host_id}")
                    host_update_params = models.HostUpdateParams(**host_update_params)
                    self.client.v2_update_host(infra_env_id=infra_env_id, host_id=host_id,
                                               host_update_params=host_update_params)
                elif not bind_updated:
                    warning("Nothing updated for this host")

    def wait_hosts(self, name, number=3, filter_installed=False):
        infra_env_id = self.get_infra_env_id(name)
        while True:
            current_hosts = [host for host in self.client.v2_list_hosts(infra_env_id=infra_env_id)]
            if filter_installed:
                current_hosts = [host for host in current_hosts if host['status'] != 'installed']
            if len(current_hosts) >= number:
                return
            else:
                info("Waiting 5s for hosts to reach expected number")
                sleep(5)

    def update_cluster(self, name, overrides):
        cluster_id = self.get_cluster_id(name)
        if 'api_ip' in overrides:
            overrides['api_vip'] = overrides['api_ip']
            del overrides['api_ip']
        if 'ingress_ip' in overrides:
            overrides['ingress_vip'] = overrides['ingress_ip']
            del overrides['ingress_ip']
        if 'pull_secret' in overrides:
            pull_secret = os.path.expanduser(overrides['pull_secret'])
            if os.path.exists(pull_secret):
                overrides['pull_secret'] = re.sub(r"\s", "", open(pull_secret).read())
            else:
                warning("Using pull_secret as string")
        if 'role' in overrides:
            role = overrides['role']
            hosts_roles = [{"id": host['id'], "role": role} for host in self.client.list_hosts(cluster_id=cluster_id)]
            overrides['hosts_roles'] = hosts_roles
            del overrides['role']
        installconfig = {}
        if 'network_type' in overrides:
            installconfig['networking'] = {'networkType': overrides['network_type']}
            del overrides['network_type']
        if 'sno_disk' in overrides:
            sno_disk = overrides['sno_disk']
            if '/dev' not in sno_disk:
                sno_disk = f'/dev/{sno_disk}'
            installconfig['BootstrapInPlace'] = {'InstallationDisk': sno_disk}
            del overrides['sno_disk']
        if 'tpm' in overrides and overrides['tpm']:
            installconfig['disk_encryption'] = {"enable_on": "all", "mode": "tpmv2"}
        if 'tang_servers' in overrides:
            tang_servers = overrides['tang_servers']
            if isinstance(tang_servers, list):
                tang_servers = ','.join(tang_servers)
            installconfig['disk_encryption'] = {"enable_on": "all", "mode": "tpmv2", "tang_servers": tang_servers}
        if 'installconfig' in overrides:
            installconfig = overrides['installconfig']
            del overrides['installconfig']
        if installconfig:
            self.client.v2_update_cluster_install_config(cluster_id, json.dumps(installconfig))
        if 'sno' in overrides:
            del overrides['sno']
        if 'tpm' in overrides:
            del overrides['tpm']
        if 'tang_servers' in overrides:
            del overrides['tang_servers']
        if 'static_network_config' in overrides:
            del overrides['static_network_config']
        for key in ['openshift_version', 'sshKey']:
            if key in overrides:
                del overrides[key]
        if 'olm_operators' in overrides:
            overrides['olm_operators'] = self.set_olm_operators(overrides['olm_operators'])
        if 'machine_networks' in overrides:
            overrides['machine_networks'] = self.set_machine_networks(cluster_id, overrides['machine_networks'])
        if 'service_networks' in overrides:
            overrides['service_networks'] = self.set_service_networks(cluster_id, overrides['service_networks'])
        if 'cluster_networks' in overrides:
            overrides['cluster_networks'] = self.set_cluster_networks(cluster_id, overrides['cluster_networks'])
        if overrides:
            cluster_update_params = models.V2ClusterUpdateParams(**overrides)
            self.client.v2_update_cluster(cluster_id=cluster_id, cluster_update_params=cluster_update_params)

    def start_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        cluster_info = self.client.v2_get_cluster(cluster_id=cluster_id).to_dict()
        if cluster_info['status'] == 'adding-hosts':
            infra_env_id = self.get_infra_env_id(name)
            for host in self.client.v2_list_hosts(infra_env_id=infra_env_id):
                host_id = host['id']
                self.client.v2_install_host(infra_env_id=infra_env_id, host_id=host_id)
        else:
            self.client.v2_install_cluster(cluster_id=cluster_id)

    def stop_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        self.client.v2_reset_cluster(cluster_id=cluster_id)

    def upload_manifests(self, name, directory, openshift=False):
        cluster_id = self.get_cluster_id(name)
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
                warning(f"skipping file {_fic}")
                continue
            info(f"uploading file {_fic}")
            content = base64.b64encode(open(f"{directory}/{_fic}").read().encode()).decode("UTF-8")
            folder = 'manifests' if not openshift else 'openshift'
            manifest_info = {'file_name': _fic, 'content': content, 'folder': folder}
            create_manifest_params = models.CreateManifestParams(**manifest_info)
            manifests_api.v2_create_cluster_manifest(cluster_id, create_manifest_params)

    def list_manifests(self, name):
        results = []
        cluster_id = self.get_cluster_id(name)
        manifests_api = api.ManifestsApi(api_client=self.api)
        manifests = manifests_api.v2_list_cluster_manifests(cluster_id)
        for manifest in manifests:
            results.append({'file_name': manifest['file_name'], 'folder': manifest['folder']})
        return results

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
                error("installconfig is not set")
                sys.exit(1)
            if not isinstance(installconfig, dict):
                error("installconfig is not in correct format")
                sys.exit(1)
        self.client.v2_update_cluster_install_config(cluster_id, json.dumps(installconfig))

    def update_iso(self, name, overrides={}):
        iso_overrides = overrides.copy()
        infra_env_id = self.get_infra_env_id(name)
        if 'ignition_config_override'not in iso_overrides:
            ignition_config_override = self.set_disconnected_ignition_config_override(infra_env_id, iso_overrides)
            if ignition_config_override is not None:
                iso_overrides['ignition_config_override'] = ignition_config_override
        self.update_infra_env(name, overrides=iso_overrides)

    def info_service(self):
        versionapi = api.VersionsApi(api_client=self.api)
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

    def create_infra_env(self, name, overrides={}):
        allowed_parameters = ["name", "openshift_version", "proxy", "cpu_architecture", "pull_secret",
                              "ssh_authorized_key", "static_network_config", "additional_ntp_sources",
                              "image_type", "ignition_config_override", "cluster_id"]
        existing_ids = [x['id'] for x in self.list_infra_envs() if x['name'] == name]
        if existing_ids:
            error(f"Infraenv {name} already there. Leaving")
            sys.exit(1)
        self.set_default_values(overrides)
        self.set_default_infraenv_values(overrides)
        new_infraenv_params = default_infraenv_params
        new_infraenv_params['name'] = name
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
        allowed_parameters = ["proxy", "pull_secret", "ssh_authorized_key", "static_network_config",
                              "additional_ntp_sources", "image_type", "ignition_config_override"]
        infra_env_id = self.get_infra_env_id(name)
        self.set_default_values(overrides)
        self.set_default_infraenv_values(overrides)
        infra_env_update_params = {}
        for parameter in overrides:
            if parameter in allowed_parameters:
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
                            info(f"Waiting 5s for host {host_name} to get unbound")
                            sleep(5)
            info(f"Binding Host {host_name} to Cluster {cluster}")
            bind_host_params = {'cluster_id': cluster_id}
            bind_host_params = models.BindHostParams(**bind_host_params)
            self.client.bind_host(infra_env_id, host_id, bind_host_params)

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
