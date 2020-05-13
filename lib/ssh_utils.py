import os
import sys
import time
import globals

def run_cmd(cmd):
    cmd_stdout = ""
    tmpfile = "/tmp/pf9.{}.tmp".format(os.getppid())
    cmd_exitcode = os.system("{} > {} 2>&1".format(cmd,tmpfile))

    # read output of command
    if os.path.isfile(tmpfile):
        try:
            fh_tmpfile = open(tmpfile, 'r')
            cmd_stdout = fh_tmpfile.readlines()
        except:
            None

    os.remove(tmpfile)
    return cmd_exitcode, cmd_stdout


def run_cmd_ssh(host_ip, ssh_username, ssh_key, cmd):
    cmd = "ssh -o StrictHostKeyChecking=no -i {} {}@{} {}".format(ssh_key, ssh_username, host_ip, cmd)
    exit_status, stdout = run_cmd(cmd)
    if exit_status == 0:
        return(True, stdout)
    else:
        return(False, None)


def test_ip_via_ssh(ssh_key, ssh_username, host_ip):
    cmd = "ssh -o StrictHostKeyChecking=no -i {} {}@{} 'echo 201'".format(ssh_key, ssh_username, host_ip)
    exit_status, stdout = run_cmd(cmd)
    if exit_status == 0:
        return(True)
    else:
        return(False)


def wait_for_ip(du, host_ip, ci_logger=None):
    TIMEOUT = 3
    POLL_INTERVAL = 10
    timeout = int(time.time()) + (60 * TIMEOUT)
    flag_ip_responding = False
    message = "waiting for ip to respond using: ssh {}@{}): ".format(du['auth_username'],host_ip)
    sys.stdout.write(message)
    sys.stdout.flush()

    while True:
        ip_status = test_ip_via_ssh(du['auth_ssh_key'],du['auth_username'],host_ip)
        if ip_status:
            flag_ip_responding = True
            break
        elif int(time.time()) > timeout:
            break
        else:
            time.sleep(POLL_INTERVAL)

    # enforce TIMEOUT
    if not flag_ip_responding:
        message = "TIMEOUT"
        if ci_logger:
            ci_logger(message)
        else:
            sys.stdout.write("{}\n".format(message))
            sys.stdout.flush()
        return(False)

    if ci_logger:
        ci_logger("OK")
    else:
        sys.stdout.write("OK\n")
        sys.stdout.flush()
    return(True)


def validate_login(du_metadata, host_ip):
    if du_metadata['auth_type'] == "simple":
        return(False)
    elif du_metadata['auth_type'] == "sshkey":
        cmd = "ssh -o StrictHostKeyChecking=no -i {} {}@{} 'echo 201'".format(du_metadata['auth_ssh_key'], du_metadata['auth_username'], host_ip)
        exit_status, stdout = run_cmd(cmd)
        if exit_status == 0:
            return(True)
        else:
            return(False)

    return(False)

