from assisted_service_client import ApiClient, Configuration, api, models
from ailib.common import warning, error, info
import os
import re
import sys
import yaml
from shutil import copyfileobj
from uuid import uuid4


# default_cluster_params = {"openshift_version": "4.6", "base_dns_domain": "karmalabs.com",
#                          "cluster_network_cidr": "string", "cluster_network_host_prefix": 24,
#                          "service_network_cidr": "string", "vip_dhcp_allocation": False}
default_cluster_params = {"openshift_version": "4.6", "base_dns_domain": "karmalabs.com", "vip_dhcp_allocation": False}


class AssistedClient(object):
    def __init__(self, url):
        self.url = url
        configs = Configuration()
        configs.host = self.url + "/api/assisted-install/v1"
        configs.verify_ssl = False
        # self.set_config_auth(configs)
        self.api = ApiClient(configuration=configs)
        self.client = api.InstallerApi(api_client=self.api)

    def get_cluster_id(self, name):
        matching_ids = [x['id'] for x in self.list_clusters() if x['name'] == name]
        if matching_ids:
            return matching_ids[0]
        else:
            error("Cluster %s not found" % name)
            os._exit(1)

    def get_cluster_name(self, _id):
        matching_names = [x['name'] for x in self.list_clusters() if x['id'] == _id]
        if matching_names:
            return matching_names[0]
        else:
            error("Cluster %s not found" % _id)
            os._exit(1)

    def create_cluster(self, name, overrides={}):
        allowed_parameters = ["name", "openshift_version", "base_dns_domain", "cluster_network_cidr",
                              "cluster_network_host_prefix", "service_network_cidr", "ingress_vip", "pull_secret",
                              "ssh_public_key", "vip_dhcp_allocation", "http_proxy", "https_proxy", "no_proxy"]
        if '-day2' in name:
            self.create_day2_cluster(name)
            return
        if 'pull_secret' not in overrides:
            warning("No pull_secret file path provided as parameter. Using openshift_pull.json")
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
                del overrides['pub_key']
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

    def create_day2_cluster(self, name):
        name = name.replace('-day2', '')
        cluster_id = self.get_cluster_id(name)
        cluster = self.client.get_cluster(cluster_id=cluster_id)
        cluster_version = cluster.openshift_version
        ssh_public_key = cluster.image_info.ssh_public_key
        api_name = "api." + name + "." + cluster.base_dns_domain
        response = self.client.download_cluster_files(cluster_id=cluster_id, file_name="install-config.yaml",
                                                      _preload_content=False)
        data = yaml.safe_load(response.read().decode("utf-8"))
        pull_secret = data.get('pullSecret')
        cluster_params = {"openshift_version": cluster_version, "api_vip_dnsname": api_name}
        new_cluster_id = str(uuid4())
        new_name = name + "-day2"
        new_cluster = models.AddHostsClusterCreateParams(name=new_name, id=new_cluster_id, **cluster_params)
        self.client.register_add_hosts_cluster(new_add_hosts_cluster_params=new_cluster)
        cluster_update_params = {'pull_secret': pull_secret, 'ssh_public_key': ssh_public_key}
        cluster_update_params = models.ClusterUpdateParams(**cluster_update_params)
        self.client.update_cluster(cluster_id=new_cluster_id, cluster_update_params=cluster_update_params)

    def create_iso(self, name, overrides):
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
        image_create_params = models.ImageCreateParams(ssh_public_key=ssh_public_key)
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
            if len(hostids) == 1 and 'name' in overrides:
                newname = overrides['name']
                info("renaming node %s as %s in cluster %s" % (hostname, newname, cluster_name))
                hosts_names = [{"id": hostids[0], "hostname": newname}]
            elif len(hostids) == 1 and 'requested_hostname' in overrides:
                newname = overrides['requested_hostname']
                info("renaming node %s as %s in cluster %s" % (hostname, newname, cluster_name))
                hosts_names = [{"id": hostids[0], "hostname": newname}]
            else:
                node = role if role is not None else 'node'
                hosts_names = []
                for index, hostid in enumerate(hostids):
                    newname = "%s-%s" % (node, index)
                    info("renaming node %s as %s in cluster %s" % (hostid, newname, cluster_name))
                    new_host = {"id": hostid, "hostname": newname}
                    hosts_names.append(new_host)
            cluster_update_params['hosts_names'] = hosts_names
            if cluster_update_params:
                cluster_update_params = models.ClusterUpdateParams(**cluster_update_params)
                self.client.update_cluster(cluster_id=cluster_id, cluster_update_params=cluster_update_params)

    def update_cluster(self, name, overrides):
        cluster_id = self.get_cluster_id(name)
        cluster_update_params = {}
        if 'api_ip' in overrides:
            cluster_update_params['api_vip'] = overrides['api_ip']
        if 'api_vip' in overrides:
            cluster_update_params['api_vip'] = overrides['api_vip']
        if 'ingress_ip' in overrides:
            cluster_update_params['ingress_vip'] = overrides['ingress_ip']
        if 'ingress_vip' in overrides:
            cluster_update_params['ingress_vip'] = overrides['ingress_vip']
        if 'domain' in overrides:
            cluster_update_params['base_dns_domain'] = overrides['domain']
        if 'base_dns_domain' in overrides:
            cluster_update_params['base_dns_domain'] = overrides['base_dns_domain']
        if 'ssh_public_key' in overrides:
            cluster_update_params['ssh_public_key'] = overrides['ssh_public_key']
        if 'pull_secret' in overrides:
            pull_secret = os.path.expanduser(overrides['pull_secret'])
            if os.path.exists(pull_secret):
                cluster_update_params['pull_secret'] = re.sub(r"\s", "", open(pull_secret).read())
        if 'baremetal_machine_cidr' in overrides:
            cluster_update_params['machine_network_cidr'] = overrides['baremetal_machine_cidr']
        if 'machine_network_cidr' in overrides:
            cluster_update_params['machine_network_cidr'] = overrides['machine_network_cidr']
        if 'role' in overrides:
            role = overrides['role']
            hosts_roles = [{"id": host['id'], "role": role} for host in self.client.list_hosts(cluster_id=cluster_id)]
            cluster_update_params['hosts_roles'] = hosts_roles
        if cluster_update_params:
            cluster_update_params = models.ClusterUpdateParams(**cluster_update_params)
            self.client.update_cluster(cluster_id=cluster_id, cluster_update_params=cluster_update_params)

    def start_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        if '-day2' in name:
            base_name = name.replace('-day2', '')
            base_cluster_id = self.get_cluster_id(base_name)
            base_cluster = self.client.get_cluster(cluster_id=base_cluster_id)
            cluster_update_params = {'api_vip': base_cluster.api_vip, 'base_dns_domain': base_cluster.base_dns_domain}
            cluster_update_params = models.ClusterUpdateParams(**cluster_update_params)
            self.client.update_cluster(cluster_id=cluster_id, cluster_update_params=cluster_update_params)
            self.client.install_hosts(cluster_id=cluster_id)
        else:
            self.client.install_cluster(cluster_id=cluster_id)
