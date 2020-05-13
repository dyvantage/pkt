##############################################################################################################
## PKT : Toolkit for Packet.net
##############################################################################################################
import os
import sys

# early functions
def fail(m=None):
    sys.stdout.write("ASSERT: {}\n".format(m))
    sys.exit(1)

# validate python version
if not sys.version_info[0] in [2,3]:
    fail("Unsupported Python Version: {}\n".format(sys.version_info[0]))

# configure where to look for modules
SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, 'lib')))

# import modules
import globals, urllib3, requests, json, signal, argparse, packet_cloud, interview, express_cli, pf9_pmk
from encrypt import Encryption
from packet_cloud import PacketCloud

# disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# functions
def _parse_args():
    ap = argparse.ArgumentParser(sys.argv[0], formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--apply", "-a",  help="apply <path-to-specfile>", required=False, nargs=1)
    ap.add_argument("--show", "-s",  help="show <resource>", required=False, nargs=1, choices=['plan','os','facility','server'])
    ap.add_argument("--dump", "-p",  help="dump <uuid>", required=False, nargs=1)
    ap.add_argument("--terminate", "-t",  help="terminate <uuid>", required=False, nargs=1)
    ap.add_argument("--encrypt", "-e",  help="encrypt a string", required=False, nargs=1)
    ap.add_argument("--unencrypt", "-u",  help="decrypt a string", required=False, nargs=1)
    ap.add_argument("--cryptoKey", "-c", help="Encryption key for decrypting secure data", required=False, nargs=1)
    ap.add_argument("--kubeconfig", "-k", help="get getKubeconfig <cluster-uuid>", required=False, nargs=1)
    ap.add_argument("--debug", "-g",  help="set debug <parameter> to True", required=False, nargs=1, choices=['skip_launch','stop_after_launch'])
    return ap.parse_args()

def motd():
    try:
        target_fh = open(globals.PKT_BANNER, 'r')
        sys.stdout.write("\n{}\n".format(target_fh.read()))
        target_fh.close()
    except:
        None

    sys.stdout.write("Welcome to PKT!\n")
    sys.stdout.write("Run: 'pkt -h' for usage information\n")

def init_install_dir():
    if not os.path.isdir(globals.INSTALL_DIR):
        try:
            os.mkdir(globals.INSTALL_DIR)
        except:
            fail("failed to create directory: {}".format(globals.INSTALL_DIR))

def read_config():
    if not os.path.isfile(globals.CONFIG_FILE):
        fail("config file missing: {}".format(globals.CONFIG_FILE))

    if sys.version_info[0] == 2:
        import ConfigParser
        app_config = ConfigParser.ConfigParser()
    else:
        import configparser
        app_config = configparser.ConfigParser()

    try:
        app_config.read(globals.CONFIG_FILE)
        return(app_config)
    except Exception as ex:
        fail("ConfigParser.Exception: {}\n".format(ex.message))

def write_config(config_values):
    try:
        config_fh = open(globals.CONFIG_FILE, "w")
        config_fh.write("[packet.net]\n")
        config_fh.write("token = {}\n".format(config_values['pkt_api_key']))
        config_fh.write("project_id = {}\n".format(config_values['pkt_project_id']))
        config_fh.write("\n[platform9.net]\n")
        config_fh.write("region_url = {}\n".format(config_values['pf9_region_url']))
        config_fh.write("username = {}\n".format(config_values['pf9_username']))
        config_fh.write("password = {}\n".format(config_values['pf9_password']))
        config_fh.write("tenant = {}\n".format(config_values['pf9_tenant']))
        config_fh.write("region = {}\n".format(config_values['pf9_region']))
        config_fh.write("express_cli_branch = {}\n".format(config_values['pf9_express_cli_branch']))
        config_fh.close()
    except:
        fail("failed to write config file: {}\n".format(globals.CONFIG_FILE))

    # validate config was written
    if not os.path.isfile(globals.CONFIG_FILE):
        fail("failed to write config file: {}\n".format(globals.CONFIG_FILE))

def init_keyfile(encryption_key):
    if os.path.isfile(globals.ENCRYPTION_KEY_FILE):
        try:
            os.remove(globals.ENCRYPTION_KEY_FILE)
        except:
            fail("failed to remove keyfile: {}".format(globals.ENCRYPTION_KEY_FILE))

    # write user-supplied encryption key to keyfile
    try:
        data_file_fh = open(globals.ENCRYPTION_KEY_FILE, "w")
        data_file_fh.write("{}".format(encryption_key))
        data_file_fh.close()
    except:
        fail("failed to initialize keyfile for encryption: {}".format(globals.ENCRYPTION_KEY_FILE))


###########################################################################################
## main
###########################################################################################
def main():
    args = _parse_args()

    # validate installation directory
    init_install_dir()

    # initialize encryption/decryption key (keyfile)
    if args.cryptoKey:
        init_keyfile(args.key[0])
        sys.exit(0)

    # initialize encryption
    encryption = Encryption(globals.ENCRYPTION_KEY_FILE)

    # encryption functions
    if args.encrypt:
        sys.stdout.write("Encrypted string: {}\n".format(encryption.encrypt_string(args.encrypt[0])))
        sys.exit(0)
    elif args.unencrypt:
        sys.stdout.write("Decrypted string: {}\n".format(encryption.decrypt_string(args.unencrypt[0])))
        sys.exit(0)

    # display banner (if no commandline arguments passed)
    if not len(sys.argv) > 1:
        motd()

    # prompt user for Packet & Platform9 credentials (if config_file is missing)
    if not os.path.isfile(globals.CONFIG_FILE):
        config_values = interview.get_config()
        if config_values:
            write_config(config_values)

    # read config file
    app_config = read_config()

    # update ctx
    globals.ctx['packet']['project_id'] = app_config.get('packet.net','project_id')
    globals.ctx['packet']['token'] = encryption.decrypt_string(app_config.get('packet.net','token'))
    globals.ctx['platform9']['region_url'] = app_config.get('platform9.net','region_url')
    globals.ctx['platform9']['username'] = app_config.get('platform9.net','username')
    globals.ctx['platform9']['password'] = encryption.decrypt_string(app_config.get('platform9.net','password'))
    globals.ctx['platform9']['tenant'] = app_config.get('platform9.net','tenant')
    globals.ctx['platform9']['region'] = app_config.get('platform9.net','region')
    globals.ctx['platform9']['express_cli_branch'] = app_config.get('platform9.net','express_cli_branch')

    # validate encryption
    if not globals.ctx['packet']['token']:
        fail("failed to decrypt API key")

    # init packet cloud
    packet_cloud = PacketCloud(globals.ctx['packet']['token'], globals.ctx['packet']['project_id'])

    # validate credentials
    valid_creds = packet_cloud.validate_creds()
    if not valid_creds:
        try:
            os.remove(globals.CONFIG_FILE)
        except:
            sys.stdout.write("ERROR: failed to remove config file with invalid credentials: {}\n".format(globals.CONFIG_FILE))
        fail("failed to login into Packet.net with the supplied credentials\n")

    # init Platform9 Cloud
    sys.stdout.write("\n[Initializing Platform9]\n")
    from pf9_pmk import PMK
    pf9_cloud = PMK(
        globals.ctx['platform9']['region_url'],
        globals.ctx['platform9']['username'],
        globals.ctx['platform9']['password'],
        globals.ctx['platform9']['tenant']
    )

    # validate login to Platform9
    if not pf9_cloud.validate_login():
        sys.stdout.write("ERROR: failed to login to PMK region: {} (user={}/tenant={})\n".format(
            globals.ctx['platform9']['region_url'],globals.ctx['platform9']['username'],globals.ctx['platform9']['tenant'])
        )
    else:
        sys.stdout.write("--> logged into PMK region: {} (user={}/tenant={})\n".format(
            globals.ctx['platform9']['region_url'],globals.ctx['platform9']['username'],globals.ctx['platform9']['tenant'])
        )

    # manage debug parameters
    if args.debug and args.debug[0] == "skip_launch":
        globals.flag_skip_launch = True
    if args.debug and args.debug[0] == "stop_after_launch":
        globals.flag_stop_after_launch = True

    # run function (based on commandline args)
    if args.apply:
        packet_cloud.run_action(args.apply[0])
    elif args.terminate:
        if not packet_cloud.delete_instance(args.delete[0]):
            fail("failed to delete instance")
        sys.stdout.write("instance deleted\n")
    elif args.dump:
        packet_cloud.dump_device_record(args.dump[0])
    elif args.kubeconfig:
        if not pf9_cloud.download_kubeconfig(args.kubeconfig[0]):
            fail("failed to download kubeconfig")
    elif args.show and args.show[0] == "plan":
        packet_cloud.show_plans()
    elif args.show and args.show[0] == "os":
        packet_cloud.show_operating_systems()
    elif args.show and args.show[0] == "facility":
        packet_cloud.show_facilities()
    elif args.show and args.show[0] == "server":
        packet_cloud.show_devices()

    # exit cleanly
    sys.exit(0)

if __name__ == "__main__":
    main()
