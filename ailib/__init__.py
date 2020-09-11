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
        matching_ids = [x['id'] for x in self.list() if x['name'] == name]
        if matching_ids:
            return matching_ids[0]
        else:
            error("Cluster %s not found" % name)
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
        print(self.client.register_cluster(new_cluster_params=cluster_params))

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

    def list(self):
        return self.client.list_clusters()
