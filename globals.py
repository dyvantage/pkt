"""Global Variable Defaults"""
from os.path import expanduser
import os

# working directory
HOME_DIR = "{}".format(expanduser("~"))
INSTALL_DIR = "{}/.packet".format(HOME_DIR)
PKT_BANNER = "{}/conf/banner.txt".format(os.path.dirname(os.path.realpath(__file__)))

# initialize config context
ctx = {
    "packet": {},
    "platform9": {}
}

# file for storing unique encryption key
ENCRYPTION_KEY_FILE = "{}/.keyfile".format(INSTALL_DIR)

# configuration file
CONFIG_FILE = "{}/pkt.conf".format(HOME_DIR)

# packet API
API_BASEURL = "https://api.packet.net"
INSTANCE_LAUNCH_TIMEOUT = 20

# express-cli
EXPRESS_BASE_DIR = "{}/pf9".format(HOME_DIR)
EXPRESS_LOG_DIR = "{}/pf9/log".format(HOME_DIR)
EXPRESS_CONFIG_DIR = "{}/config".format(EXPRESS_BASE_DIR)
EXPRESS_CLI_INSTALL_DIR = "{}/express-cli".format(INSTALL_DIR)
EXPRESS_CLI_URL = "https://github.com/platform9/express-cli.git"

# debug variables
flag_skip_launch = False
flag_stop_after_launch = False
