from assisted_service_client import ApiClient, Configuration, api, models
from ailib.common import warning, error, info, get_token
import base64
import json
import os
import re
import sys
import yaml
import urllib
from shutil import copyfileobj
from uuid import uuid4


# default_cluster_params = {"openshift_version": "4.6", "base_dns_domain": "karmalabs.com",
#                          "cluster_network_cidr": "string", "cluster_network_host_prefix": 24,
#                          "service_network_cidr": "string", "vip_dhcp_allocation": False}
default_cluster_params = {"openshift_version": "4.8", "base_dns_domain": "karmalabs.com", "vip_dhcp_allocation": False}

IGNITION_VERSIONS = {'4.6': '3.1.0', '4.7': '3.2.0', '4.8': '3.2.0', '4.9': '3.2.0'}


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
                warning("Detected proxy env var without scheme, updating proxy to %s" % proxy)
            config.proxy = proxy
        aihome = "%s/.aicli" % os.environ['HOME']
        if not os.path.exists(aihome):
            os.mkdir(aihome)
        if url in ['https://api.openshift.com', 'https://api.stage.openshift.com']:
            if offlinetoken is None:
                if os.path.exists('%s/offlinetoken.txt' % aihome):
                    offlinetoken = open('%s/offlinetoken.txt' % aihome).read().strip()
                else:
                    error("offlinetoken needs to be set to gather token for %s" % url)
                    error("get it at https://cloud.redhat.com/openshift/token")
                    if os.path.exists('/i_am_a_container'):
                        error("use -e AI_OFFLINETOKEN=$AI_OFFLINETOKEN to expose it in container mode")
                    sys.exit(1)
            if not os.path.exists('%s/offlinetoken.txt' % aihome):
                with open('%s/offlinetoken.txt' % aihome, 'w') as f:
                    f.write(offlinetoken)
            if os.path.exists('%s/token.txt' % aihome):
                token = open('%s/token.txt' % aihome).read().strip()
            try:
                token = get_token(token=token, offlinetoken=offlinetoken)
            except:
                error("Hit issues when trying to set token")
                if os.path.exists('%s/offlinetoken.txt' % aihome):
                    error("Removing offlinetoken file")
                    os.remove('%s/offlinetoken.txt' % aihome)
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
            error("Missing pull secret file %s" % pull_secret)
            sys.exit(1)
        overrides['pull_secret'] = re.sub(r"\s", "", open(pull_secret).read())
        if 'ssh_public_key' not in overrides:
            pub_key = overrides.get('pub_key', '%s/.ssh/id_rsa.pub' % os.environ['HOME'])
            if os.path.exists(pub_key):
                overrides['ssh_public_key'] = open(pub_key).read().strip()
            else:
                error("Missing public key file %s" % pub_key)
                sys.exit(1)
            if 'public_key' in overrides:
                del overrides['public_key']
        if 'sno' in overrides:
            if overrides['sno']:
                overrides['high_availability_mode'] = "None"
            del overrides['sno']
        if 'high_availability_mode' in overrides and overrides['high_availability_mode'] is None:
            overrides['high_availability_mode'] = "None"
        if 'olm_operators' in overrides:
            olm_operators = []
            for operator in overrides['olm_operators']:
                if isinstance(operator, str):
                    olm_operators.append({'name': operator})
                elif isinstance(operator, dict) and 'name' in operator:
                    olm_operators.append(operator)
                else:
                    error("Invalid entry for olm_operators %s" % operator)
                    sys.exit(1)
            overrides['olm_operators'] = olm_operators
        if 'tpm' in overrides and overrides['tpm']:
            overrides['disk_encryption'] = {"enable_on": "all", "mode": "tpmv2"}
            del overrides['tpm']
        if 'tang_servers' in overrides:
            tang_servers = overrides['tang_servers']
            if isinstance(tang_servers, list):
                tang_servers = ','.join(tang_servers)
            overrides['disk_encryption'] = {"enable_on": "all", "mode": "tpmv2", "tang_servers": tang_servers}
            del overrides['tang_servers']

    def get_cluster_id(self, name):
        matching_ids = [x['id'] for x in self.list_clusters() if x['name'] == name]
        if matching_ids:
            return matching_ids[0]
        else:
            error("Cluster %s not found" % name)
            sys.exit(1)

    def get_cluster_name(self, _id):
        matching_names = [x['name'] for x in self.list_clusters() if x['id'] == _id]
        if matching_names:
            return matching_names[0]
        else:
            error("Cluster %s not found" % _id)
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
            error("Cluster %s already there. Leaving" % name)
            sys.exit(1)
        if '-day2' in name:
            self.create_day2_cluster(name, overrides)
            return
        self.set_default_values(overrides)
        new_cluster_params = default_cluster_params
        new_cluster_params['name'] = name
        for parameter in overrides:
            if parameter in allowed_parameters:
                new_cluster_params[parameter] = overrides[parameter]
        cluster_params = models.ClusterCreateParams(**new_cluster_params)
        self.client.register_cluster(new_cluster_params=cluster_params)

    def delete_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        self.client.deregister_cluster(cluster_id=cluster_id)
        day2_matching_ids = [x['id'] for x in self.list_clusters() if x['name'] == name + '-day2']
        if day2_matching_ids:
            self.client.deregister_cluster(cluster_id=day2_matching_ids[0])

    def info_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        return self.client.get_cluster(cluster_id=cluster_id)

    def export_cluster(self, name):
        allowed_parameters = ["name", "openshift_version", "base_dns_domain", "cluster_network_cidr",
                              "cluster_network_host_prefix", "service_network_cidr", "ingress_vip",
                              "ssh_public_key", "vip_dhcp_allocation", "http_proxy", "https_proxy", "no_proxy",
                              "high_availability_mode", "user_managed_networking", "additional_ntp_source",
                              "disk_encryption", "schedulable_masters", "hyperthreading",
                              "ocp_release_image", "api_vip", "ingress_vip"]
        cluster_id = self.get_cluster_id(name)
        alldata = self.client.get_cluster(cluster_id=cluster_id).to_dict()
        data = {}
        for k in allowed_parameters:
            if k in alldata and alldata[k] is not None:
                data[k] = alldata[k]
            if k == 'disk_encryption' and alldata[k]['enable_on'] is None:
                del data[k]
        print(yaml.dump(data, default_flow_style=False, indent=2))

    def create_day2_cluster(self, name, overrides={}):
        name = name.replace('-day2', '')
        existing_ids = [x['id'] for x in self.list_clusters() if x['name'] == name]
        if not existing_ids:
            warning("Base Cluster %s not found. Populating with default values" % name)
            if 'version' in overrides:
                openshift_version = overrides['version']
            elif 'openshift_version' in overrides:
                openshift_version = overrides['openshift_version']
            else:
                openshift_version = default_cluster_params["openshift_version"]
                warning("No openshift_version provided.Using %s" % openshift_version)
            if 'domain' in overrides:
                domain = overrides['domain']
                del overrides['domain']
            elif 'base_dns_domain' in overrides:
                domain = overrides['base_dns_domain']
            else:
                domain = default_cluster_params["base_dns_domain"]
                warning("No base_dns_domain provided.Using %s" % domain)
            overrides['base_dns_domain'] = domain
            api_name = "api." + name + "." + domain
            self.set_default_values(overrides)
            pull_secret, ssh_public_key = overrides['pull_secret'], overrides['ssh_public_key']
        else:
            cluster_id = self.get_cluster_id(name)
            cluster = self.client.get_cluster(cluster_id=cluster_id)
            openshift_version = cluster.openshift_version
            ssh_public_key = cluster.image_info.ssh_public_key
            api_name = "api." + name + "." + cluster.base_dns_domain
            response = self.client.download_cluster_files(cluster_id=cluster_id, file_name="install-config.yaml",
                                                          _preload_content=False)
            data = yaml.safe_load(response.read().decode("utf-8"))
            pull_secret = data.get('pullSecret')
        cluster_params = {"openshift_version": str(openshift_version), "api_vip_dnsname": api_name}
        new_cluster_id = str(uuid4())
        new_name = name + "-day2"
        new_cluster = models.AddHostsClusterCreateParams(name=new_name, id=new_cluster_id, **cluster_params)
        self.client.register_add_hosts_cluster(new_add_hosts_cluster_params=new_cluster)
        cluster_update_params = {'pull_secret': pull_secret, 'ssh_public_key': ssh_public_key}
        cluster_update_params = models.ClusterUpdateParams(**cluster_update_params)
        self.client.update_cluster(cluster_id=new_cluster_id, cluster_update_params=cluster_update_params)

    def create_iso(self, name, overrides, minimal=False):
        cluster_id = self.get_cluster_id(name)
        if 'ssh_public_key' in overrides:
            ssh_public_key = overrides['ssh_public_key']
        else:
            pub_key = overrides.get('pub_key', '%s/.ssh/id_rsa.pub' % os.environ['HOME'])
            if os.path.exists(pub_key):
                ssh_public_key = open(pub_key).read().strip()
            else:
                error("Missing public key file %s" % pub_key)
                sys.exit(1)
        image_type = "minimal-iso" if minimal else "full-iso"
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
        image_create_params = models.ImageCreateParams(ssh_public_key=ssh_public_key, image_type=image_type,
                                                       static_network_config=static_network_config)
        self.client.generate_cluster_iso(cluster_id=cluster_id, image_create_params=image_create_params)
        iso_url = "%s/api/assisted-install/v1/clusters/%s/downloads/image" % (self.url, cluster_id)
        info("Iso available at %s" % iso_url)

    def download_iso(self, name, path):
        cluster_id = self.get_cluster_id(name)
        response = self.client.download_cluster_iso(cluster_id=cluster_id, _preload_content=False)
        with open("%s/%s.iso" % (path, name), "wb") as f:
            copyfileobj(response, f)

    def download_installconfig(self, name, path):
        cluster_id = self.get_cluster_id(name)
        response = self.client.download_cluster_files(cluster_id=cluster_id, file_name="install-config.yaml",
                                                      _preload_content=False)
        with open("%s/install-config.yaml.%s" % (path, name), "wb") as f:
            copyfileobj(response, f)

    def download_kubeadminpassword(self, name, path):
        cluster_id = self.get_cluster_id(name)
        response = self.client.download_cluster_files(cluster_id=cluster_id, file_name="kubeadmin-password",
                                                      _preload_content=False)
        with open("%s/kubeadmin-password.%s" % (path, name), "wb") as f:
            copyfileobj(response, f)

    def download_kubeconfig(self, name, path):
        cluster_id = self.get_cluster_id(name)
        response = self.client.download_cluster_files(cluster_id=cluster_id, file_name="kubeconfig-noingress",
                                                      _preload_content=False)
        with open("%s/kubeconfig.%s" % (path, name), "wb") as f:
            copyfileobj(response, f)

    def download_ignition(self, name, path, role='bootstrap'):
        cluster_id = self.get_cluster_id(name)
        response = self.client.download_cluster_files(cluster_id=cluster_id, file_name="%s.ign" % role,
                                                      _preload_content=False)
        with open("%s/%s.ign.%s" % (path, role, name), "wb") as f:
            copyfileobj(response, f)

    def list_clusters(self):
        return self.client.list_clusters()

    def list_hosts(self):
        allhosts = []
        for cluster in self.client.list_clusters():
            cluster_id = cluster['id']
            hosts = self.client.list_hosts(cluster_id=cluster_id)
            allhosts.extend(hosts)
        return allhosts

    def delete_host(self, hostname, overrides={}):
        clusters = {}
        if 'cluster' in overrides:
            cluster = overrides['cluster']
            cluster_id = self.get_cluster_id(cluster)
            hosts = self.client.list_hosts(cluster_id=cluster_id)
            matchingids = [host['id'] for host in hosts
                           if host['requested_hostname'] == hostname or host['id'] == hostname]
        else:
            for cluster in self.client.list_clusters():
                cluster_id = cluster['id']
                hosts = self.client.list_hosts(cluster_id=cluster_id)
                matchingids = [host['id'] for host in hosts
                               if host['requested_hostname'] == hostname or host['id'] == hostname]
                if matchingids:
                    clusters[cluster_id] = matchingids
        if not clusters:
            error("No Matching Host with name %s found" % hostname)
        for cluster_id in clusters:
            hostids = clusters[cluster_id]
            for host_id in hostids:
                info("Deleting Host with id %s in cluster %s" % (host_id, cluster_id))
                self.client.deregister_host(cluster_id, host_id)

    def info_host(self, hostname):
        hostinfo = None
        for cluster in self.client.list_clusters():
            cluster_id = cluster['id']
            cluster_hosts = self.client.list_hosts(cluster_id=cluster_id)
            hosts = [h for h in cluster_hosts if h['requested_hostname'] == hostname or h['id'] == hostname]
            if hosts:
                hostinfo = hosts[0]
                break
        return hostinfo

    def update_host(self, hostname, overrides):
        clusters = {}
        if 'cluster' in overrides:
            cluster = overrides['cluster']
            cluster_id = self.get_cluster_id(cluster)
            hosts = self.client.list_hosts(cluster_id=cluster_id)
            matchingids = [host['id'] for host in hosts
                           if host['requested_hostname'] == hostname or host['id'] == hostname]
        else:
            for cluster in self.client.list_clusters():
                cluster_id = cluster['id']
                hosts = self.client.list_hosts(cluster_id=cluster_id)
                matchingids = [host['id'] for host in hosts
                               if host['requested_hostname'] == hostname or host['id'] == hostname]
                if matchingids:
                    clusters[cluster_id] = matchingids
        if not clusters:
            error("No Matching Host with name %s found" % hostname)
        for cluster_id in clusters:
            base_cluster = self.client.get_cluster(cluster_id=cluster_id)
            cluster_name = base_cluster.name
            hostids = clusters[cluster_id]
            cluster_update_params = {}
            role = None
            if 'role' in overrides:
                role = overrides['role']
                hosts_roles = [{"id": hostid, "role": role} for hostid in hostids]
                cluster_update_params['hosts_roles'] = hosts_roles
            if 'name' in overrides or 'requested_hostname' in overrides:
                newname = overrides.get('name', overrides.get('requested_hostname'))
                hosts_names = []
                if len(hostids) > 1:
                    node = role if role is not None else 'node'
                    for index, hostid in enumerate(hostids):
                        newname = "%s-%s" % (node, index)
                        info("Renaming node %s as %s in cluster %s" % (hostid, newname, cluster_name))
                        new_host = {"id": hostid, "hostname": newname}
                        hosts_names.append(new_host)
                else:
                    info("Renaming node %s as %s in cluster %s" % (hostname, newname, cluster_name))
                    hosts_names = [{"id": hostids[0], "hostname": newname}]
                cluster_update_params['hosts_names'] = hosts_names
            if 'ignition' in overrides:
                for host_id in hostids:
                    # ignition_ori = self.client.get_host_ignition(cluster_id, host_id)
                    ignition_path = overrides['ignition']
                    if not os.path.exists(ignition_path):
                        warning("Ignition %s not found. Ignoring" % ignition_path)
                    else:
                        ignition_data = open(ignition_path).read()
                        host_ignition_params = models.HostIgnitionParams(config=ignition_data)
                        self.client.update_host_ignition(cluster_id, host_id, host_ignition_params=host_ignition_params)
            if 'extra_args' in overrides:
                for host_id in hostids:
                    extra_args = overrides['extra_args']
                    installer_args_params = models.InstallerArgsParams(args=extra_args)
                    self.client.update_host_installer_args(cluster_id, host_id,
                                                           installer_args_params=installer_args_params)
            if 'mcp' in overrides:
                valid_status = ["discovering", "known", "disconnected", "insufficient", "pending-for-input"]
                valid_hostids = []
                for hostid in hostids:
                    currenthost = self.client.get_host(cluster_id=cluster_id, host_id=hostid)
                    currentstatus = currenthost.status
                    if currentstatus in valid_status:
                        valid_hostids.append(hostid)
                    else:
                        error("Mcp can't be set for host %s because of incorrect status" % hostname, currentstatus)
                if valid_hostids:
                    mcp = overrides['mcp']
                    hosts_mcps = [{"id": hostid, "machine_config_pool_name": mcp} for hostid in valid_hostids]
                    cluster_update_params['hosts_machine_config_pool_names'] = hosts_mcps
            if cluster_update_params:
                cluster_update_params = models.ClusterUpdateParams(**cluster_update_params)
                self.client.update_cluster(cluster_id=cluster_id, cluster_update_params=cluster_update_params)
            else:
                warning("Nothing updated for this host")

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
        if 'network_type' in overrides or 'sno_disk' in overrides:
            installconfig = {}
            if 'network_type' in overrides:
                installconfig['networking'] = {'networkType': overrides['network_type']}
                del overrides['network_type']
            if 'sno_disk' in overrides:
                sno_disk = overrides['sno_disk']
                if '/dev' not in sno_disk:
                    sno_disk = '/dev/%s' % sno_disk
                installconfig['BootstrapInPlace'] = {'InstallationDisk': sno_disk}
                del overrides['sno_disk']
            if 'tpm' in overrides and overrides['tpm']:
                installconfig['disk_encryption'] = {"enable_on": "all", "mode": "tpmv2"}
            if 'tang_servers' in overrides:
                tang_servers = overrides['tang_servers']
                if isinstance(tang_servers, list):
                    tang_servers = ','.join(tang_servers)
                installconfig['disk_encryption'] = {"enable_on": "all", "mode": "tpmv2", "tang_servers": tang_servers}
            self.client.update_cluster_install_config(cluster_id, json.dumps(installconfig))
        if 'sno' in overrides:
            del overrides['sno']
        if 'tpm' in overrides:
            del overrides['tpm']
        if 'tang_servers' in overrides:
            del overrides['tang_servers']
        if 'static_network_config' in overrides:
            del overrides['static_network_config']
        if overrides:
            cluster_update_params = models.ClusterUpdateParams(**overrides)
            self.client.update_cluster(cluster_id=cluster_id, cluster_update_params=cluster_update_params)

    def start_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        if '-day2' in name:
            self.client.install_hosts(cluster_id=cluster_id)
        else:
            self.client.install_cluster(cluster_id=cluster_id)

    def stop_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        self.client.reset_cluster(cluster_id=cluster_id)

    def upload_manifests(self, name, directory, openshift=False):
        cluster_id = self.get_cluster_id(name)
        if not os.path.exists(directory):
            error("Directory %s not found" % directory)
            sys.exit(1)
        elif not os.path.isdir(directory):
            error("%s is not a directory" % directory)
            sys.exit(1)
        manifests_api = api.ManifestsApi(api_client=self.api)
        _fics = os.listdir(directory)
        if not _fics:
            error("No files found in directory %s" % directory)
            sys.exit(0)
        for _fic in _fics:
            if not _fic.endswith('.yml') and not _fic.endswith('.yaml'):
                warning("skipping file %s" % _fic)
                continue
            info("uploading file %s" % _fic)
            content = base64.b64encode(open("%s/%s" % (directory, _fic)).read().encode()).decode("UTF-8")
            folder = 'manifests' if not openshift else 'openshift'
            manifest_info = {'file_name': _fic, 'content': content, 'folder': folder}
            create_manifest_params = models.CreateManifestParams(**manifest_info)
            manifests_api.create_cluster_manifest(cluster_id, create_manifest_params)

    def list_manifests(self, name):
        results = []
        cluster_id = self.get_cluster_id(name)
        manifests_api = api.ManifestsApi(api_client=self.api)
        manifests = manifests_api.list_cluster_manifests(cluster_id)
        for manifest in manifests:
            results.append({'file_name': manifest['file_name'], 'folder': manifest['folder']})
        return results

    def patch_installconfig(self, name, overrides={}):
        cluster_id = self.get_cluster_id(name)
        installconfig = {}
        if 'network_type' in overrides or 'sno_disk' in overrides:
            if 'network_type' in overrides:
                installconfig['networking'] = {'networkType': overrides['network_type']}
            if 'sno_disk' in overrides:
                sno_disk = overrides['sno_disk']
                if '/dev' not in sno_disk:
                    sno_disk = '/dev/%s' % sno_disk
                installconfig['BootstrapInPlace'] = {'InstallationDisk': sno_disk}
        else:
            installconfig = overrides.get('installconfig')
            if installconfig is None:
                error("installconfig is not set")
                sys.exit(1)
            if not isinstance(installconfig, dict):
                error("installconfig is not in correct format")
                sys.exit(1)
        self.client.update_cluster_install_config(cluster_id, json.dumps(installconfig))

    def patch_iso(self, name, overrides={}):
        cluster_id = self.get_cluster_id(name)
        openshift_version = str(self.info_cluster(name).to_dict()['openshift_version'])
        ignition_version = IGNITION_VERSIONS.get(openshift_version, '3.2.0')
        discovery_ignition = {}
        ailibdir = os.path.dirname(warning.__code__.co_filename)
        disconnected_url = overrides.get('disconnected_url')
        if disconnected_url is None:
            error("disconnected_url is not set")
            sys.exit(1)
        else:
            ca = overrides.get('disconnected_ca')
            if ca is None:
                if 'installconfig' in overrides and isinstance(overrides['installconfig'], dict)\
                        and 'additionalTrustBundle' in overrides['installconfig']:
                    info("using cert from installconfig/additionalTrustBundle")
                    ca = overrides['installconfig']['additionalTrustBundle']
                else:
                    error("disconnected_ca is not set")
                    sys.exit(1)
        with open("%s/registries.conf.templ" % ailibdir) as f:
            data = f.read()
            registries = data % {'url': disconnected_url}
        registries_encoded = base64.b64encode(registries.encode()).decode("UTF-8")
        ca_encoded = base64.b64encode(ca.encode()).decode("UTF-8")
        fil1 = {"path": "/etc/containers/registries.conf", "mode": 420, "overwrite": True, "user": {"name": "root"},
                "contents": {"source": "data:text/plain;base64,%s" % registries_encoded}}
        fil2 = {"path": "/etc/pki/ca-trust/source/anchors/domain.crt", "mode": 420, "overwrite": True,
                "user": {"name": "root"}, "contents": {"source": "data:text/plain;base64,%s" % ca_encoded}}
        discovery_ignition = {"config": json.dumps({"ignition": {"version": ignition_version},
                                                    "storage": {"files": [fil1, fil2]}})}
        discovery_ignition_params = models.DiscoveryIgnitionParams(**discovery_ignition)
        self.client.update_discovery_ignition(cluster_id, discovery_ignition_params)

    def info_service(self):
        versionapi = api.VersionsApi(api_client=self.api)
        supported_versions = versionapi.list_supported_openshift_versions()
        print("supported openshift versions:")
        for version in supported_versions:
            print(version)
        operatorsapi = api.OperatorsApi(api_client=self.api)
        supported_operators = operatorsapi.list_supported_operators()
        print("supported operators:")
        for operator in sorted(supported_operators):
            print(operator)
