import sys
import os
import globals
import user_io
from encrypt import Encryption


def get_config():
    config_values = {
    }

    # get Packet credentials
    sys.stdout.write("\nPlease enter credentials for Packet.Net:\n")
    project_id = user_io.read_kbd("--> Project ID", [], '', True, True)
    if project_id == "q":
        return ''

    api_key = user_io.read_kbd("--> API Key", [], '', False, True)
    if api_key == "q":
        return ''

    # get Platform9 credentials
    sys.stdout.write("\nPlease enter credentials for Platform9.Com:\n")
    pf9_region_url = user_io.read_kbd("--> PMK Region URL", [], '', True, True)
    if pf9_region_url == "q":
        return ''

    pf9_username = user_io.read_kbd("--> Username", [], '', True, True)
    if pf9_username == "q":
        return ''

    pf9_password = user_io.read_kbd("--> Password", [], '', False, True)
    if pf9_password == "q":
        return ''

    pf9_tenant = user_io.read_kbd("--> Tenant", [], 'service', True, True)
    if pf9_tenant == "q":
        return ''

    pf9_region = user_io.read_kbd("--> Region Name", [], 'RegionOne', True, True)
    if pf9_region == "q":
        return ''

    pf9_express_cli_branch = user_io.read_kbd("--> Express-CLI Branch", [], 'tomchris/restructure', True, True)
    if pf9_express_cli_branch == "q":
        return ''

    # initialize encryption
    encryption = Encryption(globals.ENCRYPTION_KEY_FILE)

    # update config (encrypt api_key)
    config_values['pkt_project_id'] = project_id
    config_values['pkt_api_key'] = encryption.encrypt_string(api_key)
    config_values['pf9_region_url'] = pf9_region_url
    config_values['pf9_username'] = pf9_username
    config_values['pf9_password'] = encryption.encrypt_string(pf9_password)
    config_values['pf9_tenant'] = pf9_tenant
    config_values['pf9_region'] = pf9_region
    config_values['pf9_express_cli_branch'] = pf9_express_cli_branch

    sys.stdout.write("\n")
    return(config_values)

