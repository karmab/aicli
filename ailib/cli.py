import argparse
from argparse import RawDescriptionHelpFormatter as rawhelp
from ailib import AssistedClient
from ailib.common import get_overrides, info, error, success
from prettytable import PrettyTable
import os
import sys


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
        if paramfile is not None:
            paramfile = "/workdir/%s" % paramfile
        elif os.path.exists("/workdir/aicli_parameters.yml"):
            paramfile = "/workdir/aicli_parameters.yml"
            info("Using default parameter file aicli_parameters.yml")
    elif paramfile is None and os.path.exists("aicli_parameters.yml"):
        paramfile = "aicli_parameters.yml"
        info("Using default parameter file aii_parameters.yml")
    return paramfile


def create_cluster(args):
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url)
    ai.create_cluster(args.cluster, overrides)


def delete_cluster(args):
    success("Deleting cluster %s" % args.cluster)
    ai = AssistedClient(args.url)
    ai.delete_cluster(args.cluster)


def info_cluster(args):
    skipped = ['kind', 'href', 'ssh_public_key', 'http_proxy', 'https_proxy', 'no_proxy', 'pull_secret_set',
               'vip_dhcp_allocation', 'validations_info']
    ai = AssistedClient(args.url)
    info = ai.info_cluster(args.cluster).to_dict()
    for entry in info:
        if entry not in skipped:
            print("%s: %s" % (entry, info[entry]))


def list_cluster(args):
    ai = AssistedClient(args.url)
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
    ai = AssistedClient(args.url)
    hosts = ai.list_hosts(args.cluster)
    hoststable = PrettyTable(["Host", "Id", "Status", "Role"])
    for host in sorted(hosts, key=lambda x: x['requested_hostname']):
        name = host['requested_hostname']
        _id = host['id']
        role = host['role']
        status = host['status']
        entry = [name, _id, status, role]
        hoststable.add_row(entry)
    print(hoststable)


def create_iso(args):
    success("Creating Iso for Cluster %s" % args.cluster)
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url)
    ai.create_iso(args.cluster, overrides)


def download_iso(args):
    success("Downloading Iso for Cluster %s" % args.cluster)
    ai = AssistedClient(args.url)
    ai.download_iso(args.cluster)


def download_kubeconfig(args):
    success("Downloading Kubeconfig for Cluster %s in kubeconfig.%s" % (args.cluster, args.cluster))
    ai = AssistedClient(args.url)
    ai.download_kubeconfig(args.cluster)


def update_host(args):
    success("Updating Host %s in Cluster %s" % (args.hostname, args.cluster))
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url)
    ai.update_host(args.cluster, args.hostname, overrides)


def update_cluster(args):
    success("Updating Cluster %s" % args.cluster)
    paramfile = choose_parameter_file(args.paramfile)
    overrides = get_overrides(paramfile=paramfile, param=args.param)
    ai = AssistedClient(args.url)
    ai.update_cluster(args.cluster, overrides)


def start_cluster(args):
    success("Starting cluster %s" % args.cluster)
    ai = AssistedClient(args.url)
    ai.start_cluster(args.cluster)


def cli():
    """

    """
    # PARAMETERS_HELP = 'specify parameter or keyword for rendering (multiple can be specified)'
    parser = argparse.ArgumentParser(description='Assisted installer assistant')
    parser.add_argument('-U', '--url', default=os.environ.get('AI_URL'))
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

    info_desc = 'Info Object'
    info_parser = subparsers.add_parser('info', description=info_desc, help=info_desc)
    info_subparsers = info_parser.add_subparsers(metavar='', dest='subcommand_info')

    list_desc = 'List Object'
    list_parser = subparsers.add_parser('list', description=list_desc, help=list_desc, aliases=['get'])
    list_subparsers = list_parser.add_subparsers(metavar='', dest='subcommand_list')

    update_desc = 'Update Object'
    update_parser = subparsers.add_parser('update', description=update_desc, help=update_desc, aliases=['launch'])
    update_subparsers = update_parser.add_subparsers(metavar='', dest='subcommand_update')

    start_desc = 'Start Object'
    start_parser = subparsers.add_parser('start', description=start_desc, help=start_desc)
    start_subparsers = start_parser.add_subparsers(metavar='', dest='subcommand_start')

    clustercreate_desc = 'Create Cluster'
    clustercreate_epilog = None
    clustercreate_parser = create_subparsers.add_parser('cluster', description=clustercreate_desc,
                                                        help=clustercreate_desc,
                                                        epilog=clustercreate_epilog, formatter_class=rawhelp)
    clustercreate_parser.add_argument('-P', '--param', action='append',
                                      help='specify parameter or keyword for rendering (multiple can be specified)',
                                      metavar='PARAM')
    clustercreate_parser.add_argument('--paramfile', help='Parameters file', metavar='PARAMFILE')
    clustercreate_parser.add_argument('cluster', metavar='CLUSTER')
    clustercreate_parser.set_defaults(func=create_cluster)

    isocreate_desc = 'Create iso'
    isocreate_epilog = None
    isocreate_parser = create_subparsers.add_parser('iso', description=isocreate_desc, help=isocreate_desc,
                                                    epilog=isocreate_epilog, formatter_class=rawhelp)
    isocreate_parser.add_argument('-P', '--param', action='append',
                                  help='specify parameter or keyword for rendering (multiple can be specified)',
                                  metavar='PARAM')
    isocreate_parser.add_argument('--paramfile', help='Parameters file', metavar='PARAMFILE')
    isocreate_parser.add_argument('cluster', metavar='CLUSTER')
    isocreate_parser.set_defaults(func=create_iso)

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
    clusterinfo_parser.add_argument('cluster', metavar='CLUSTER')
    clusterinfo_parser.set_defaults(func=info_cluster)

    clusterupdate_desc = 'Update Cluster'
    clusterupdate_parser = argparse.ArgumentParser(add_help=False)
    clusterupdate_parser.add_argument('-P', '--param', action='append',
                                      help='specify parameter or keyword for rendering (multiple can be specified)',
                                      metavar='PARAM')
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

    isodownload_desc = 'Download Iso'
    isodownload_parser = argparse.ArgumentParser(add_help=False)
    isodownload_parser.add_argument('cluster', metavar='CLUSTER')
    isodownload_parser.set_defaults(func=download_iso)
    download_subparsers.add_parser('iso', parents=[isodownload_parser],
                                   description=isodownload_desc,
                                   help=isodownload_desc)

    kubeconfigdownload_desc = 'Download Kubeconfig'
    kubeconfigdownload_parser = argparse.ArgumentParser(add_help=False)
    kubeconfigdownload_parser.add_argument('cluster', metavar='CLUSTER')
    kubeconfigdownload_parser.set_defaults(func=download_kubeconfig)
    download_subparsers.add_parser('kubeconfig', parents=[kubeconfigdownload_parser],
                                   description=kubeconfigdownload_desc,
                                   help=kubeconfigdownload_desc)

    clusterlist_desc = 'List Clusters'
    clusterlist_parser = argparse.ArgumentParser(add_help=False)
    clusterlist_parser.set_defaults(func=list_cluster)
    list_subparsers.add_parser('cluster', parents=[clusterlist_parser], description=clusterlist_desc,
                               help=clusterlist_desc, aliases=['clusters'])

    hostslist_desc = 'List Hosts'
    hostslist_parser = argparse.ArgumentParser(add_help=False)
    hostslist_parser.add_argument('cluster', metavar='CLUSTER')
    hostslist_parser.set_defaults(func=list_hosts)
    list_subparsers.add_parser('host', parents=[hostslist_parser], description=hostslist_desc,
                               help=clusterlist_desc, aliases=['hosts'])

    hostupdate_desc = 'Update Host'
    hostupdate_parser = argparse.ArgumentParser(add_help=False)
    hostupdate_parser.add_argument('-P', '--param', action='append',
                                   help='specify parameter or keyword for rendering (multiple can be specified)',
                                   metavar='PARAM')
    hostupdate_parser.add_argument('--paramfile', help='Parameters file', metavar='PARAMFILE')
    hostupdate_parser.add_argument('cluster', metavar='CLUSTER')
    hostupdate_parser.add_argument('hostname', metavar='HOSTNAME')
    hostupdate_parser.set_defaults(func=update_host)
    update_subparsers.add_parser('host', parents=[hostupdate_parser], description=hostupdate_desc, help=hostupdate_desc)

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
        error("Specify a valid url with -U flag or set environment variable AI_URL")
        os._exit(1)
    args.func(args)


if __name__ == '__main__':
    cli()
