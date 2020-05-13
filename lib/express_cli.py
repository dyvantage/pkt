import os
import sys
import time
import globals
import ssh_utils
import user_io
import subprocess


def validate_installation():
    exit_status, stdout = ssh_utils.run_cmd("express --version")
    if exit_status == 0:
        return(True)
    return(False)


def init(url, username, password, tenant, region):
    sys.stdout.write("\n[Initialize Express-CLI (branch = {})]\n".format(globals.ctx['platform9']['express_cli_branch']))

    # validate express base directory exists
    if not os.path.isdir(globals.EXPRESS_BASE_DIR):
        try:
            os.mkdir(globals.EXPRESS_BASE_DIR)
        except:
            sys.stdout.write("ERROR: failed to create directory: {}\n".format(globals.EXPRESS_BASE_DIR))
            sys.exit(1)

    # validate express log directory exists
    if not os.path.isdir(globals.EXPRESS_LOG_DIR):
        try:
            os.mkdir(globals.EXPRESS_LOG_DIR)
        except:
            sys.stdout.write("ERROR: failed to create directory: {}\n".format(globals.EXPRESS_LOG_DIR))
            sys.exit(1)

    if not install_express_cli():
        sys.stdout.write("ERROR: failed to install express-cli\n")
        return(False)
    if not validate_installation():
        sys.stdout.write("ERROR: missing pip package: express-cli\n")
        return(False)
    if not build_config(url, username, password, tenant, region):
        sys.stdout.write("ERROR: failed to build express-cli config file\n")
        return(False)

    return(True)


def get_express_branch(git_branch, repo_basedir):
    if not os.path.isdir(repo_basedir):
        return(None)

    cmd = "cd {} && git symbolic-ref --short -q HEAD".format(repo_basedir)
    exit_status, stdout = ssh_utils.run_cmd(cmd)
    if exit_status != 0:
        return(None)

    return(stdout[0].strip())
    

def checkout_branch(git_branch, install_dir):
    cmd = "cd {} && git checkout {}".format(install_dir, git_branch)
    sys.stdout.write("cmd={}".format(cmd))
    exit_status, stdout = ssh_utils.run_cmd(cmd)

    current_branch = get_express_branch(git_branch, install_dir)
    if current_branch != git_branch:
        return(False)

    return(True)


def get_express_cli_branch():
    if not os.path.isdir(globals.EXPRESS_CLI_INSTALL_DIR):
        return(None)

    cmd = "cd {} && git symbolic-ref --short -q HEAD".format(globals.EXPRESS_CLI_INSTALL_DIR)
    exit_status, stdout = ssh_utils.run_cmd(cmd)
    if exit_status != 0:
        return(None)

    return(stdout[0].strip())
    

def install_express_cli():
    if not os.path.isdir(globals.EXPRESS_CLI_INSTALL_DIR):
        cmd = "git clone {} {}".format(globals.EXPRESS_CLI_URL, globals.EXPRESS_CLI_INSTALL_DIR)
        sys.stdout.write("--> cloning repository ({})\n".format(cmd))
        exit_status, stdout = ssh_utils.run_cmd(cmd)
        if not os.path.isdir(globals.EXPRESS_CLI_INSTALL_DIR):
            sys.stdout.write("ERROR: failed to clone Express-CLI Repository\n")
            return(False)

    sys.stdout.write("--> refreshing repository (git fetch -a)\n")
    cmd = "cd {}; git fetch -a".format(globals.EXPRESS_CLI_INSTALL_DIR)
    exit_status, stdout = ssh_utils.run_cmd(cmd)
    if exit_status != 0:
        sys.stdout.write("ERROR: failed to fetch branches (git fetch -)\n")
        return(False)

    current_branch = get_express_cli_branch()
    sys.stdout.write("--> current branch: {}\n".format(current_branch))
    sys.stdout.write("--> target branch: {}\n".format(globals.ctx['platform9']['express_cli_branch']))
    if current_branch != globals.ctx['platform9']['express_cli_branch']:
        sys.stdout.write("--> switching branches: {}\n".format(globals.ctx['platform9']['express_cli_branch']))
        if (checkout_branch(globals.ctx['platform9']['express_cli_branch'],globals.EXPRESS_CLI_INSTALL_DIR)) == False:
            sys.stdout.write("ERROR: failed to checkout git branch: {}\n".format(globals.EXPRESS_CLI_BRANCH))
            return(False)

    cmd = "cd {}; git pull origin {}".format(globals.EXPRESS_CLI_INSTALL_DIR,globals.ctx['platform9']['express_cli_branch'])
    sys.stdout.write("--> pulling latest code (git pull origin {})\n".format(globals.ctx['platform9']['express_cli_branch']))
    exit_status, stdout = ssh_utils.run_cmd(cmd)
    if exit_status != 0:
        sys.stdout.write("ERROR: failed to pull latest code (git pull origin {})\n".format(globals.ctx['platform9']['express_cli_branch']))
        return(False)
 
    sys.stdout.write("--> pip installing express-cli\n")
    cmd = "cd {}; pip install -e .".format(globals.EXPRESS_CLI_INSTALL_DIR)
    exit_status, stdout = ssh_utils.run_cmd(cmd)
    if exit_status != 0:
        for line in stdout:
            sys.stdout.write("{}\n".format(line))
        sys.stdout.write("ERROR: initialization failed\n")
        return(False)
    return(True)


def build_config(url, username, password, tenant, region):
    sys.stdout.write("--> building configuration file\n")
    
    cmd = "express config create --du_url {} --os_username {} --os_password '{}' --os_region {} --os_tenant {}".format(
        url.replace('https://',''), username, password, region, tenant
    )
    exit_status, stdout = ssh_utils.run_cmd(cmd)
    if exit_status != 0:
        for l in stdout:
            sys.stdout.write(l)
        return(False)

    return(True)


def activate_config(url):
    sys.stdout.write("--> Activating configuration file: {}\n".format(url))
    
    cmd = "express config activate {}".format(url)
    exit_status, stdout = ssh_utils.run_cmd(cmd)
    if exit_status != 0:
        for l in stdout:
            sys.stdout.write(l)
        return(False)

    return(True)


def wait_for_job(p):
    cnt = 0
    minute = 1
    while True:
        if cnt == 0:
            sys.stdout.write(".")
        elif (cnt % 9) == 0:
            sys.stdout.write("|")
            if (minute % 6) == 0:
                sys.stdout.write("\n")
            cnt = -1
            minute += 1
        else:
            sys.stdout.write(".")
        sys.stdout.flush()
        if p.poll() != None:
            break
        time.sleep(1)
        cnt += 1


def tail_log(p):
    last_line = None
    while True:
        current_line = p.stdout.readline()
        if not current_line:
            current_line = p.stderr.readline()
        if sys.version_info[0] == 2:
            sys.stdout.write(current_line)
        else:
            sys.stdout.write(current_line.decode())
        if p.poll() != None:
            if current_line == last_line:
                break
        last_line = current_line


def map_true_false(s):
    if int(s) == 1:
        return("True")
    else:
        return("False")

def build_cluster(cluster, nodes, username, ssh_key):
    sys.stdout.write("\n[Invoking Express-CLI (to orchestrate cluster provisioning)]\n")
    command_args = ['express','cluster','create','-u',username,'-s',ssh_key]
    for node in nodes:
        if node['node_type'] == "master":
            command_args.append("-m")
        else:
            command_args.append("-w")
        command_args.append(node['node_ip'])

        if node['public_ip'] != "":
            command_args.append("-f")
            command_args.append(node['public_ip'])

    # append cluster args
    if cluster['master_vip_ipv4'] != "":
        command_args.append('--masterVip')
        command_args.append(cluster['master_vip_ipv4'])
    if cluster['master_vip_iface'] != "":
        command_args.append('--masterVipIf')
        command_args.append(cluster['master_vip_iface'])
    if cluster['metallb_cidr'] != "":
        command_args.append('--metallbIpRange')
        command_args.append(cluster['metallb_cidr'])
    command_args.append('--containersCidr')
    command_args.append(cluster['containers_cidr'])
    command_args.append('--servicesCidr')
    command_args.append(cluster['services_cidr'])
    command_args.append('--privileged')
    command_args.append(map_true_false(cluster['privileged']))
    command_args.append('--appCatalogEnabled')
    command_args.append(map_true_false(cluster['app_catalog_enabled']))
    command_args.append('--allowWorkloadsOnMaster')
    command_args.append(map_true_false(cluster['allow_workloads_on_master']))
    command_args.append(cluster['name'])

    # run command (via subprocess)
    cmd = ""
    for c in command_args:
        cmd = "{} {}".format(cmd,c)
    sys.stdout.write("--> running:{}\n\n".format(cmd))
    c = subprocess.Popen(command_args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    tail_log(c)

