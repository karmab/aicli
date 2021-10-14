import argparse
from argparse import RawDescriptionHelpFormatter as rawhelp
from ailib import AssistedClient
from ailib.common import get_overrides, info, error, get_latest_rhcos_metal, get_commit_rhcos_metal
import json
from prettytable import PrettyTable
import os
import sys

PARAMHELP = "specify parameter or keyword for rendering (multiple can be specified)"


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
            paramfile = "/workdir/%s" % paramfile
        elif os.path.exists("/workdir/aicli_parameters.yml"):
            paramfile = "/workdir/aicli_parameters.yml"
            info("Using default parameter file aicli_parameters.yml")
    elif paramfile is None and os.path.exists("aicli_parameters.yml"):
        paramfile = "aicli_parameters.yml"
        info("Using default parameter file aicli_parameters.yml")
    return paramfile


def create_cluster(args):
    info("Creating cluster %s" % args.cluster)
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.create_cluster(args.cluster, overrides)


def delete_cluster(args):
    info("Deleting cluster %s" % args.cluster)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.delete_cluster(args.cluster)


def export_cluster(args):
    info("Exporting cluster %s" % args.cluster)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.export_cluster(args.cluster)


def info_cluster(args):
    if not args.full:
        skipped = ['kind', 'href', 'ssh_public_key', 'http_proxy', 'https_proxy', 'no_proxy', 'pull_secret_set',
                   'vip_dhcp_allocation', 'validations_info', 'hosts', 'image_info', 'host_networks']
    else:
        skipped = []
    fields = args.fields.split(',') if args.fields is not None else []
    values = args.values
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    info = ai.info_cluster(args.cluster).to_dict()
    if fields:
        for key in list(info):
            if key not in fields:
                del info[key]
    for key in list(info):
        if key in skipped or info[key] is None:
            del info[key]
    for entry in sorted(info):
        currententry = "%s: %s" % (entry, info[entry]) if not values else info[entry]
        print(currententry)


def delete_host(args):
    info("Updating Host %s" % args.hostname)
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.delete_host(args.hostname, overrides=overrides)


def info_host(args):
    if not args.full:
        skipped = ['kind', 'inventory', 'logs_collected_at', 'href', 'validations_info', 'discovery_agent_version',
                   'installer_version', 'progress_stages', 'connectivity']
    else:
        skipped = []
    fields = args.fields.split(',') if args.fields is not None else []
    values = args.values
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    hostinfo = ai.info_host(args.host)
    if hostinfo is None:
        error("Host %s not found" % args.host)
    else:
        if fields:
            for key in list(hostinfo):
                if key not in fields:
                    del hostinfo[key]
        for key in list(hostinfo):
            if key in skipped or hostinfo[key] is None:
                del hostinfo[key]
        for entry in sorted(hostinfo):
            currententry = "%s: %s" % (entry, hostinfo[entry]) if not values else hostinfo[entry]
            print(currententry)


def list_cluster(args):
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    clusters = ai.list_clusters()
    clusterstable = PrettyTable(["Cluster", "Id", "Status", "Dns Domain"])
    for cluster in sorted(clusters, key=lambda x: x['name']):
        name = cluster['name']
        status = cluster['status']
        _id = cluster['id']
        base_dns_domain = cluster.get('base_dns_domain', 'N/A')
        entry = [name, _id, status, base_dns_domain]
        clusterstable.add_row(entry)
    print(clusterstable)


def list_hosts(args):
    clusterids = {}
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    hosts = ai.list_hosts()
    hoststable = PrettyTable(["Host", "Cluster", "Id", "Status", "Role", "Ip"])
    for host in sorted(hosts, key=lambda x: x['requested_hostname']):
        name = host['requested_hostname']
        clusterid = host['cluster_id']
        if clusterid not in clusterids:
            clusterids[clusterid] = ai.get_cluster_name(clusterid)
        clustername = clusterids[clusterid]
        _id = host['id']
        role = host['role']
        status = host['status']
        inventory = json.loads(host['inventory']) if 'inventory' in host else {}
        ip = 'N/A'
        if 'interfaces' in inventory and inventory['interfaces']:
            if 'ipv6_addresses' in inventory['interfaces'][0] and inventory['interfaces'][0]['ipv6_addresses']:
                ip = inventory['interfaces'][0]['ipv6_addresses'][0].split('/')[0]
            if 'ipv4_addresses' in inventory['interfaces'][0] and inventory['interfaces'][0]['ipv4_addresses']:
                ip = inventory['interfaces'][0]['ipv4_addresses'][0].split('/')[0]
        entry = [name, clustername, _id, status, role, ip]
        hoststable.add_row(entry)
    print(hoststable)


def create_iso(args):
    info("Creating Iso for Cluster %s" % args.cluster)
    paramfile = choose_parameter_file(args.paramfile)
    minimal = args.minimal
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.create_iso(args.cluster, overrides, minimal=minimal)


def download_iso(args):
    info("Downloading Iso for Cluster %s in %s" % (args.cluster, args.path))
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.download_iso(args.cluster, args.path)


def download_kubeadminpassword(args):
    info("Downloading KubeAdminPassword for Cluster %s in %s/kubeadmin.%s" % (args.cluster, args.path, args.cluster))
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.download_kubeadminpassword(args.cluster, args.path)


def download_kubeconfig(args):
    info("Downloading Kubeconfig for Cluster %s in %s/kubeconfig.%s" % (args.cluster, args.path, args.cluster))
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.download_kubeconfig(args.cluster, args.path)


def download_installconfig(args):
    info("Downloading Install Config for Cluster %s in %s/install-config.yaml.%s" % (args.cluster, args.path,
                                                                                     args.cluster))
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.download_installconfig(args.cluster, args.path)


def download_metal(args):
    path = args.path
    if args.commit:
        commitcmd = "oc adm release info quay.io/ocpmetal/ocp-release:$(oc get clusterversion -o "
        commitcmd += "jsonpath='{.items[0].status.desired.version}') --commits | "
        commitcmd += "awk -F' ' ''/baremetal-installer/ {print $3}'"
        commitid = os.popen(commitcmd).read()
        metal = get_commit_rhcos_metal(commitid)
    else:
        metal = get_latest_rhcos_metal(version=args.version)
    info("Downloading metal %s in %s" % (metal, path))
    downloadcmd = "curl -L %s > %s/%s" % (metal, path, os.path.basename(metal))
    os.system(downloadcmd)


def download_ignition(args):
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    role = args.role
    ai.download_ignition(args.cluster, args.path, role=role)


def update_host(args):
    info("Updating Host %s" % args.hostname)
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.update_host(args.hostname, overrides)


def update_cluster(args):
    info("Updating Cluster %s" % args.cluster)
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.update_cluster(args.cluster, overrides)


def start_cluster(args):
    info("Starting cluster %s" % args.cluster)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.start_cluster(args.cluster)


def stop_cluster(args):
    info("Stopping cluster %s" % args.cluster)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.stop_cluster(args.cluster)


def create_manifests(args):
    info("Uploading manifests for Cluster %s" % args.cluster)
    directory = args.dir
    openshift = args.openshift
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.upload_manifests(args.cluster, directory=directory, openshift=openshift)


def list_manifests(args):
    info("Retrieving manifests for Cluster %s" % args.cluster)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    manifests = ai.list_manifests(args.cluster)
    manifeststable = PrettyTable(["File", "Folder"])
    for manifest in sorted(manifests, key=lambda x: x['file_name']):
        filename = manifest['file_name']
        folder = manifest['folder']
        entry = [filename, folder]
        manifeststable.add_row(entry)
    print(manifeststable)


def patch_installconfig(args):
    info("Patching installconfig in %s" % args.cluster)
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.patch_installconfig(args.cluster, overrides)


def patch_iso(args):
    info("Patching iso in %s" % args.cluster)
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.patch_iso(args.cluster, overrides)


def info_service(args):
    info("Retrieving information on service")
    ai = AssistedClient(args.url, token=args.token, offlinetoken=args.offlinetoken)
    ai.info_service()


def cli():
    """

    """
    # PARAMETERS_HELP = 'specify parameter or keyword for rendering (multiple can be specified)'
    parser = argparse.ArgumentParser(description='Assisted installer assistant')
    parser.add_argument('--stage', action='store_true')
    parser.add_argument('-U', '--url', default=os.environ.get('AI_URL'))
    parser.add_argument('--token', default=os.environ.get('AI_TOKEN'))
    parser.add_argument('--offlinetoken', default=os.environ.get('AI_OFFLINETOKEN'))
    subparsers = parser.add_subparsers(metavar='', title='Available Commands')

    create_desc = 'Create Object'
    create_parser = subparsers.add_parser('create', description=create_desc, help=create_desc, aliases=['add'])
    create_subparsers = create_parser.add_subparsers(metavar='', dest='subcommand_create')

    delete_desc = 'Delete Object'
    delete_parser = subparsers.add_parser('delete', description=delete_desc, help=delete_desc, aliases=['remove'])
    delete_parser.add_argument('-y', '--yes', action='store_true', help='Dont ask for confirmation', dest="yes_top")
    delete_subparsers = delete_parser.add_subparsers(metavar='', dest='subcommand_delete')

    download_desc = 'Download Assets like Iso'
    download_parser = subparsers.add_parser('download', description=download_desc, help=download_desc)
    download_subparsers = download_parser.add_subparsers(metavar='', dest='subcommand_download')

    export_desc = 'Export Object'
    export_parser = subparsers.add_parser('export', description=export_desc, help=export_desc)
    export_subparsers = export_parser.add_subparsers(metavar='', dest='subcommand_export')

    info_desc = 'Info Object'
    info_parser = subparsers.add_parser('info', description=info_desc, help=info_desc)
    info_subparsers = info_parser.add_subparsers(metavar='', dest='subcommand_info')

    list_desc = 'List Object'
    list_parser = subparsers.add_parser('list', description=list_desc, help=list_desc, aliases=['get'])
    list_subparsers = list_parser.add_subparsers(metavar='', dest='subcommand_list')

    patch_desc = 'Patch Object'
    patch_parser = subparsers.add_parser('patch', description=patch_desc, help=patch_desc)
    patch_subparsers = patch_parser.add_subparsers(metavar='', dest='subcommand_patch')

    start_desc = 'Start Object'
    start_parser = subparsers.add_parser('start', description=start_desc, help=start_desc, aliases=['launch'])
    start_subparsers = start_parser.add_subparsers(metavar='', dest='subcommand_start')

    stop_desc = 'Stop Object'
    stop_parser = subparsers.add_parser('stop', description=stop_desc, help=stop_desc, aliases=['reset'])
    stop_subparsers = stop_parser.add_subparsers(metavar='', dest='subcommand_stop')

    update_desc = 'Update Object'
    update_parser = subparsers.add_parser('update', description=update_desc, help=update_desc)
    update_subparsers = update_parser.add_subparsers(metavar='', dest='subcommand_update')

    clustercreate_desc = 'Create Cluster'
    clustercreate_epilog = None
    clustercreate_parser = create_subparsers.add_parser('cluster', description=clustercreate_desc,
                                                        help=clustercreate_desc,
                                                        epilog=clustercreate_epilog, formatter_class=rawhelp)
    clustercreate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    clustercreate_parser.add_argument('--paramfile', help='Parameters file', metavar='PARAMFILE')
    clustercreate_parser.add_argument('cluster', metavar='CLUSTER')
    clustercreate_parser.set_defaults(func=create_cluster)

    isocreate_desc = 'Create iso'
    isocreate_epilog = None
    isocreate_parser = create_subparsers.add_parser('iso', description=isocreate_desc, help=isocreate_desc,
                                                    epilog=isocreate_epilog, formatter_class=rawhelp)
    isocreate_parser.add_argument('-m', '--minimal', action='store_true', help='Use minimal iso')
    isocreate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    isocreate_parser.add_argument('--paramfile', help='Parameters file', metavar='PARAMFILE')
    isocreate_parser.add_argument('cluster', metavar='CLUSTER')
    isocreate_parser.set_defaults(func=create_iso)

    manifestscreate_desc = 'Upload manifests to cluster'
    manifestscreate_epilog = None
    manifestscreate_parser = create_subparsers.add_parser('manifest', description=manifestscreate_desc,
                                                          help=manifestscreate_desc, epilog=manifestscreate_epilog,
                                                          formatter_class=rawhelp, aliases=['manifests'])
    manifestscreate_parser.add_argument('--dir', '--directory', help='directory with stored manifests', required=True)
    manifestscreate_parser.add_argument('-o', '--openshift', action='store_true', help='Store in openshift folder')
    manifestscreate_parser.add_argument('cluster', metavar='CLUSTER')
    manifestscreate_parser.set_defaults(func=create_manifests)

    clusterdelete_desc = 'Delete Cluster'
    clusterdelete_epilog = None
    clusterdelete_parser = delete_subparsers.add_parser('cluster', description=clusterdelete_desc,
                                                        help=clusterdelete_desc,
                                                        epilog=clusterdelete_epilog, formatter_class=rawhelp)
    clusterdelete_parser.add_argument('cluster', metavar='CLUSTER')
    clusterdelete_parser.set_defaults(func=delete_cluster)

    clusterinfo_desc = 'Info Cluster'
    clusterinfo_epilog = None
    clusterinfo_parser = info_subparsers.add_parser('cluster', description=clusterinfo_desc, help=clusterinfo_desc,
                                                    epilog=clusterinfo_epilog, formatter_class=rawhelp)
    clusterinfo_parser.add_argument('-f', '--fields', help='Display Corresponding list of fields,'
                                    'separated by a comma', metavar='FIELDS')
    clusterinfo_parser.add_argument('-v', '--values', action='store_true', help='Only report values')
    clusterinfo_parser.add_argument('--full', action='store_true', help='Full output')
    clusterinfo_parser.add_argument('cluster', metavar='CLUSTER')
    clusterinfo_parser.set_defaults(func=info_cluster)

    clusterupdate_desc = 'Update Cluster'
    clusterupdate_parser = argparse.ArgumentParser(add_help=False)
    clusterupdate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    clusterupdate_parser.add_argument('--paramfile', help='Parameters file', metavar='PARAMFILE')
    clusterupdate_parser.add_argument('cluster', metavar='CLUSTER')
    clusterupdate_parser.set_defaults(func=update_cluster)
    update_subparsers.add_parser('cluster', parents=[clusterupdate_parser], description=clusterupdate_desc,
                                 help=clusterupdate_desc)

    clusterstart_desc = 'Start Cluster'
    clusterstart_epilog = None
    clusterstart_parser = start_subparsers.add_parser('cluster', description=clusterstart_desc,
                                                      help=clusterstart_desc,
                                                      epilog=clusterstart_epilog, formatter_class=rawhelp)
    clusterstart_parser.add_argument('cluster', metavar='CLUSTER')
    clusterstart_parser.set_defaults(func=start_cluster)

    clusterstop_desc = 'Stop Cluster'
    clusterstop_epilog = None
    clusterstop_parser = stop_subparsers.add_parser('cluster', description=clusterstop_desc,
                                                    help=clusterstop_desc,
                                                    epilog=clusterstop_epilog, formatter_class=rawhelp)
    clusterstop_parser.add_argument('cluster', metavar='CLUSTER')
    clusterstop_parser.set_defaults(func=stop_cluster)

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

    isodownload_desc = 'Download Iso'
    isodownload_parser = argparse.ArgumentParser(add_help=False)
    isodownload_parser.add_argument('-p', '--path', metavar='PATH', default='.', help='Where to download asset')
    isodownload_parser.add_argument('cluster', metavar='CLUSTER')
    isodownload_parser.set_defaults(func=download_iso)
    download_subparsers.add_parser('iso', parents=[isodownload_parser],
                                   description=isodownload_desc,
                                   help=isodownload_desc)

    installconfigdownload_desc = 'Download Installconfig'
    installconfigdownload_parser = argparse.ArgumentParser(add_help=False)
    installconfigdownload_parser.add_argument('--path', metavar='PATH', default='.', help='Where to download asset')
    installconfigdownload_parser.add_argument('cluster', metavar='CLUSTER')
    installconfigdownload_parser.set_defaults(func=download_installconfig)
    download_subparsers.add_parser('installconfig', parents=[installconfigdownload_parser],
                                   description=installconfigdownload_desc,
                                   help=installconfigdownload_desc)

    kubepassworddownload_desc = 'Download Kubeadmin-password'
    kubepassworddownload_parser = argparse.ArgumentParser(add_help=False)
    kubepassworddownload_parser.add_argument('--path', metavar='PATH', default='.', help='Where to download asset')
    kubepassworddownload_parser.add_argument('cluster', metavar='CLUSTER')
    kubepassworddownload_parser.set_defaults(func=download_kubeadminpassword)
    download_subparsers.add_parser('kubeadmin-password', parents=[kubepassworddownload_parser],
                                   description=kubepassworddownload_desc,
                                   help=kubepassworddownload_desc)

    kubeconfigdownload_desc = 'Download Kubeconfig'
    kubeconfigdownload_parser = argparse.ArgumentParser(add_help=False)
    kubeconfigdownload_parser.add_argument('--path', metavar='PATH', default='.', help='Where to download asset')
    kubeconfigdownload_parser.add_argument('cluster', metavar='CLUSTER')
    kubeconfigdownload_parser.set_defaults(func=download_kubeconfig)
    download_subparsers.add_parser('kubeconfig', parents=[kubeconfigdownload_parser],
                                   description=kubeconfigdownload_desc,
                                   help=kubeconfigdownload_desc)

    metaldownload_desc = 'Download Metal file'
    metaldownload_parser = argparse.ArgumentParser(add_help=False)
    metaldownload_parser.add_argument('--commit', action='store_true', help='Use commit id')
    metaldownload_parser.add_argument('-p', '--path', metavar='PATH', default='.', help='Where to download asset')
    metaldownload_parser.add_argument('-v', '--version', metavar='VERSION', default='4.6',
                                      help='Version to use.Defaults to 4.6')
    metaldownload_parser.set_defaults(func=download_metal)
    download_subparsers.add_parser('metalfile', parents=[metaldownload_parser],
                                   description=metaldownload_desc,
                                   help=metaldownload_desc)

    clusterexport_desc = 'Export Clusters'
    clusterexport_parser = argparse.ArgumentParser(add_help=False)
    clusterexport_parser.add_argument('cluster', metavar='CLUSTER')
    clusterexport_parser.set_defaults(func=export_cluster)
    export_subparsers.add_parser('cluster', parents=[clusterexport_parser], description=clusterexport_desc,
                                 help=clusterexport_desc, aliases=['clusters'])

    clusterlist_desc = 'List Clusters'
    clusterlist_parser = argparse.ArgumentParser(add_help=False)
    clusterlist_parser.set_defaults(func=list_cluster)
    list_subparsers.add_parser('cluster', parents=[clusterlist_parser], description=clusterlist_desc,
                               help=clusterlist_desc, aliases=['clusters'])

    hostdelete_desc = 'Delete host'
    hostdelete_parser = argparse.ArgumentParser(add_help=False)
    hostdelete_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    hostdelete_parser.add_argument('--paramfile', help='Parameters file', metavar='PARAMFILE')
    hostdelete_parser.add_argument('hostname', metavar='HOSTNAME')
    hostdelete_parser.set_defaults(func=delete_host)
    delete_subparsers.add_parser('host', parents=[hostdelete_parser], description=hostdelete_desc, help=hostdelete_desc)

    hostinfo_desc = 'Info Host'
    hostinfo_epilog = None
    hostinfo_parser = info_subparsers.add_parser('host', description=hostinfo_desc, help=hostinfo_desc,
                                                 epilog=hostinfo_epilog, formatter_class=rawhelp)
    hostinfo_parser.add_argument('-f', '--fields', help='Display Corresponding list of fields,'
                                 'separated by a comma', metavar='FIELDS')
    hostinfo_parser.add_argument('-v', '--values', action='store_true', help='Only report values')
    hostinfo_parser.add_argument('--full', action='store_true', help='Full output')
    hostinfo_parser.add_argument('host', metavar='HOST')
    hostinfo_parser.set_defaults(func=info_host)

    hostslist_desc = 'List Hosts'
    hostslist_parser = argparse.ArgumentParser(add_help=False)
    hostslist_parser.set_defaults(func=list_hosts)
    list_subparsers.add_parser('host', parents=[hostslist_parser], description=hostslist_desc,
                               help=clusterlist_desc, aliases=['hosts'])

    hostupdate_desc = 'Update Host name and role'
    hostupdate_parser = argparse.ArgumentParser(add_help=False)
    hostupdate_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    hostupdate_parser.add_argument('--paramfile', help='Parameters file', metavar='PARAMFILE')
    hostupdate_parser.add_argument('hostname', metavar='HOSTNAME')
    hostupdate_parser.set_defaults(func=update_host)
    update_subparsers.add_parser('host', parents=[hostupdate_parser], description=hostupdate_desc, help=hostupdate_desc)

    manifestslist_desc = 'List Manifests of a cluster'
    manifestslist_parser = argparse.ArgumentParser(add_help=False)
    manifestslist_parser.add_argument('cluster', metavar='CLUSTER')
    manifestslist_parser.set_defaults(func=list_manifests)
    list_subparsers.add_parser('manifest', parents=[manifestslist_parser], description=manifestslist_desc,
                               help=manifestslist_desc, aliases=['manifests'])

    isopatch_desc = 'Patch Iso'
    isopatch_parser = argparse.ArgumentParser(add_help=False)
    isopatch_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    isopatch_parser.add_argument('--paramfile', help='Parameters file', metavar='PARAMFILE')
    isopatch_parser.add_argument('cluster', metavar='CLUSTER')
    isopatch_parser.set_defaults(func=patch_iso)
    patch_subparsers.add_parser('iso', parents=[isopatch_parser], description=isopatch_desc, help=isopatch_desc)

    installconfigpatch_desc = 'Patch Installconfig'
    installconfigpatch_parser = argparse.ArgumentParser(add_help=False)
    installconfigpatch_parser.add_argument('-P', '--param', action='append', help=PARAMHELP, metavar='PARAM')
    installconfigpatch_parser.add_argument('--paramfile', help='Parameters file', metavar='PARAMFILE')
    installconfigpatch_parser.add_argument('cluster', metavar='CLUSTER')
    installconfigpatch_parser.set_defaults(func=patch_installconfig)
    patch_subparsers.add_parser('installconfig', parents=[installconfigpatch_parser],
                                description=installconfigpatch_desc, help=installconfigpatch_desc)

    serviceinfo_desc = 'Info Service'
    serviceinfo_epilog = None
    serviceinfo_parser = info_subparsers.add_parser('service', description=serviceinfo_desc, help=serviceinfo_desc,
                                                    epilog=serviceinfo_epilog, formatter_class=rawhelp)
    serviceinfo_parser.set_defaults(func=info_service)

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
    if args.url is not None:
        info("Using %s as base url" % args.url)
    elif not ('subcommand_download' in vars(args) and args.subcommand_download == 'metalassets'):
        args.url = "https://api.openshift.com" if not args.stage else "https://api.stage.openshift.com"
    args.func(args)


if __name__ == '__main__':
    cli()
