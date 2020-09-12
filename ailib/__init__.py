from assisted_service_client import ApiClient, Configuration, api, models
from ailib.common import warning, error
import os
import re
import sys
from shutil import copyfileobj

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
        new_cluster_params.update(overrides)
        new_cluster_params['name'] = name
        cluster_params = models.ClusterCreateParams(**new_cluster_params)
        self.client.register_cluster(new_cluster_params=cluster_params)

    def delete_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        self.client.deregister_cluster(cluster_id=cluster_id)

    def info_cluster(self, name):
        cluster_id = self.get_cluster_id(name)
        return self.client.get_cluster(cluster_id=cluster_id)

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

    def download_iso(self, name):
        cluster_id = self.get_cluster_id(name)
        response = self.client.download_cluster_iso(cluster_id=cluster_id, _preload_content=False)
        with open("%s.iso" % name, "wb") as f:
            copyfileobj(response, f)

    def download_kubeconfig(self, name):
        cluster_id = self.get_cluster_id(name)
        # response = self.client.download_cluster_kubeconfig(cluster_id=cluster_id, _preload_content=False)
        response = self.client.download_cluster_files(cluster_id=cluster_id, file_name="kubeconfig-noingress",
                                                      _preload_content=False)
        with open("kubeconfig.%s" % name, "wb") as f:
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

    def update_host(self, name, hostname, overrides):
        cluster_id = self.get_cluster_id(name)
        hostids = [host['id'] for host in self.client.list_hosts(cluster_id=cluster_id)
                   if host['requested_hostname'] == hostname or host['id'] == hostname]
        if not hostids:
            error("No Matching Host with name %s found" % hostname)
        cluster_update_params = {}
        role = None
        if 'role' in overrides:
            role = overrides['role']
            hosts_roles = [{"id": hostid, "role": role} for hostid in hostids]
            cluster_update_params['hosts_roles'] = hosts_roles
        if len(hostids) > 1:
            node = role if role is not None else 'node'
            hosts_names = [{"id": hostid, "hostname": "%s-%s" % (node, index)} for index, hostid in enumerate(hostids)]
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
        self.client.install_cluster(cluster_id=cluster_id)
