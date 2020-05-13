import os
import sys
import requests
import json
import globals
import reports
import time
import ssh_utils
from encrypt import Encryption


class PacketCloud:
    """Interact with Packet Cloud"""
    def __init__(self, token, project_id):
        self.token = token
        self.project_id = project_id


    def validate_creds(self):
        try:
            api_endpoint = "/projects/{}/plans".format(self.project_id)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            rest_response = requests.get("{}/{}".format(globals.API_BASEURL,api_endpoint), verify=False, headers=headers)
            if rest_response.status_code == 200:
                return(True)
        except:
            return(False)

        return(False)


    def wait_for_instances(self, instance_uuids):
        booted_instances = []
        start_time = int(time.time())
        TIMEOUT = globals.INSTANCE_LAUNCH_TIMEOUT
        POLL_INTERVAL = 15
        timeout = int(time.time()) + (60 * TIMEOUT)
        flag_all_active = False
        while True:
            # loop over all instances and get status
            for tmp_uuid in instance_uuids:
                instance_status = self.get_instance_status(tmp_uuid)
                if instance_status == "active":
                    if not tmp_uuid in booted_instances:
                        booted_instances.append(tmp_uuid)
                time.sleep(1)

            # check if all instances have become active
            tmp_flag = True
            for tmp_uuid in instance_uuids:
                if not tmp_uuid in booted_instances:
                    tmp_flag = False
                    break

            if tmp_flag:
                flag_all_active = True
                break
            elif int(time.time()) > timeout:
                break
            else:
                time.sleep(POLL_INTERVAL)

        # enforce TIMEOUT
        if not flag_all_active:
            return(False,0)

        # calculate time to launch all instances
        end_time = int(time.time())
        time_elapsed = end_time - start_time

        return(True,time_elapsed)
        

    def launch_instance(self, hostname, action):
        post_payload = {
            'batches': [
                {
                    'hostname': hostname,
                    'facility': action['facility'],
                    'plan': action['plan'],
                    'operating_system': action['operating_system'],
                    'userdata': action['userdata'],
                    'customdata': action['customdata'],
                    'quantity': 1,
                    'ip_addresses': action['ip_addresses']
                }
            ]
        }

        # perform post operation
        try:
            api_endpoint = "projects/{}/devices/batch".format(self.project_id)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            rest_response = requests.post("{}/{}".format(globals.API_BASEURL,api_endpoint), verify=False, headers=headers, data=json.dumps(post_payload))
            if rest_response.status_code != 201:
                return(None, rest_response.text)
        except Exception as ex:
            sys.stdout.write("ERROR: failed to launch instance (exception.message={})\n".format(ex.message))
            return(None, ex.message)

        # parse rest response
        try:
            json_response = json.loads(rest_response.text)
            time.sleep(10)
            instance_uuid = self.get_device_uuid(hostname)
            if not instance_uuid:
                return(None, "WARNING: instance launch delayed (state={})".format(json_response['batches'][0]['state']))
            return(instance_uuid, "instance launched successfully")
        except Exception as ex1:
            sys.stdout.write("INFO: failed to launch instance (failed to retrieve the batch id)\n")
            return(None, "failed to retrieve the server id (exception.message={})".format(ex1.message))


    def launch_batch_instances(self, action):
        # valid action JSON
        required_keys = ['num_instances','plan','facility','operating_system','hostname_base','network_mode','ip_addresses','k8s_vlan_tag']
        for key_name in required_keys:
            if not key_name in action:
                sys.stdout.write("ERROR: missing required key in action: {}\n".format(key_name))
                return(None)

        # prepare to launch instances
        table_title = "-------------- Action Parameters --------------"
        table_columns = ["Operation Type","Plan","Data Center","Operating System","Hostname Base","# Instances"]
        table_rows = [ 
            [action['operation'],action['plan'], action['facility'], action['operating_system'], action['hostname_base'], action['num_instances']]
        ]
        reports.display_table(table_title, table_columns, table_rows)
        
        # launch instances
        sys.stdout.write("\n[Launching Instances]\n")
        instance_uuids = []
        LAUNCH_INTERVAL = 5
        cnt = 1
        while cnt <= action['num_instances']:
            target_hostname = "{}{}".format(action['hostname_base'], str(cnt).zfill(2))

            # validate host does not exists | TODO: update to allow for duplicate hostnames
            instance_uuid = self.get_device_uuid(target_hostname)
            if instance_uuid and (not globals.flag_skip_launch):
                sys.stdout.write("FATAL: existing host with identical name found in inventory\n")
                sys.exit(0)

            if globals.flag_skip_launch:
                sys.stdout.write("--> skipping (globals.flag_skip_launch = {})\n".format(globals.flag_skip_launch))
            else:
                sys.stdout.write("--> launching {}\n".format(target_hostname))
                instance_uuid, launch_message = self.launch_instance(target_hostname, action)
                if not instance_uuid:
                    sys.stdout.write("ERROR: failed to launch instance ({})\n".format(launch_message))
                    sys.exit(0)
                time.sleep(LAUNCH_INTERVAL)

            instance_uuids.append(instance_uuid)
            cnt += 1

        return(instance_uuids)


    def run_action(self, spec_file):
        if not os.path.isfile(spec_file):
            sys.stdout.write("ERROR: failed to open spec file: {}".format(spec_file))
            return(None)

        with open(spec_file) as json_file:
            spec_actions = json.load(json_file)

        required_keys = ['actions']
        for key_name in required_keys:
            if not key_name in spec_actions:
                sys.stdout.write("ERROR: missing required key in spec file: {}".format(key_name))
                return(None)

        # initialize flags
        flag_launched = False
        flag_assimilated = False

        # loop over actions (run sequentially/synchronously)
        instance_uuids = []
        assimilated_servers = {}
        for action in spec_actions['actions']:
            if 'operation' not in action:
                sys.stdout.write("ERROR: invalid json syntax, missing: operation\n")
                continue

            # invoke action-specific functions
            if action['operation'] == "imported-instances":
                flag_assimilated = True
                assimilated_servers = action['instances']
                print("assimilated_servers = {}".format(assimilated_servers))
                sys.stdout.write("\n[Validating Assimilated Instances]\n")
            if action['operation'] == "launch-instance":
                flag_launched = True
                required_keys = ['num_instances','hostname_base','plan','facility','operating_system','userdata','customdata','ip_addresses']
                for key_name in required_keys:
                    if not key_name in action:
                        sys.stdout.write("ERROR: missing required key in spec file: {}".format(key_name))
                        return(None)

                instance_uuids = self.launch_batch_instances(action)
                if instance_uuids:
                    sys.stdout.write("\n[Waiting for All Instances to Boot]\n")
                    all_instances_booted, boot_time = self.wait_for_instances(instance_uuids)
                    if all_instances_booted:
                        sys.stdout.write("--> all instances booted successfully, boot time = {} seconds\n\n".format(boot_time))
                        self.show_devices(instance_uuids)
                    else:
                        sys.stdout.write("--> TIMEOUT exceeded\n")
                        sys.exit(0)
 
                    # manage network_type
                    if not globals.flag_skip_launch:
                        if 'network_mode' in action and action['network_mode'] == "hybrid":
                            sys.stdout.write("\n[Setting {} Network Mode - All Instances]\n".format(action['network_mode']))
                            if not self.set_batch_hybrid_mode(instance_uuids):
                                sys.stdout.write("ERROR: failed to set one or more nodes to hybrid mode\n")
                                sys.exit(0)

                        # vlan assignment
                        if 'k8s_vlan_tag' in action and action['k8s_vlan_tag'] != "":
                            sys.stdout.write("\n[Configuring Layer-2 Networking - All Instances]\n")
                            self.assign_batch_vlan(instance_uuids, action['k8s_vlan_tag'])

                    # early exit (if global flag is set)
                    if globals.flag_stop_after_launch:
                        sys.stdout.write("\nEarly Exit (globals.flag_stop_after_launch = {})\n".format(globals.flag_stop_after_launch))
                        sys.exit(0)
            elif action['operation'] == "pf9-build-cluster":
                required_keys = ['cluster','ssh_username','ssh_key','masters','workers']
                for key_name in required_keys:
                    if not key_name in action:
                        sys.stdout.write("ERROR: missing required key in spec file: {}".format(key_name))
                        return(None)
                    if action[key_name] == "":
                        sys.stdout.write("ERROR: required key cannot be null: {}".format(key_name))
                        return(None)

                # initialize encryption
                encryption = Encryption(globals.ENCRYPTION_KEY_FILE)

                # initialize/login in Platform9 PMK
                sys.stdout.write("\n[Initializing PMK Integration]\n")
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
                    return(None)
                else:
                    sys.stdout.write("--> logged into PMK region: {} (user={}/tenant={})\n".format(
                        globals.ctx['platform9']['region_url'],globals.ctx['platform9']['username'],globals.ctx['platform9']['tenant'])
                    )

                # build node list
                node_list = []
                for node in action['masters']:
                    if flag_launched:
                        tmp_public_ip = self.get_public_ip(node['hostname'])
                    elif flag_assimilated:
                        tmp_public_ip = assimilated_servers[node['hostname']]
                    else:
                        sys.stdout.write("WARNING: invalid condition: either flag_launched or flag_assimilated must be set\n")
                        continue

                    node_entry = {
                        "hostname": node['hostname'],
                        "node_ip": node['node_ip'],
                        "node_ip_mask": node['node_ip_mask'],
                        "node_ip_interface": node['interface'],
                        "public_ip": tmp_public_ip,
                        "node_type": "master"
                    }
                    node_list.append(node_entry)

                for node in action['workers']:
                    if flag_launched:
                        tmp_public_ip = self.get_public_ip(node['hostname'])
                    elif flag_assimilated:
                        tmp_public_ip = assimilated_servers[node['hostname']]
                    else:
                        sys.stdout.write("WARNING: invalid condition: either flag_launched or flag_assimilated must be set\n")
                        continue

                    node_entry = {
                        "hostname": node['hostname'],
                        "node_ip": node['node_ip'],
                        "node_ip_mask": node['node_ip_mask'],
                        "node_ip_interface": node['interface'],
                        "public_ip": tmp_public_ip,
                        "node_type": "worker"
                    }
                    node_list.append(node_entry)

                table_title = "\n-------------- Kubernetes Cluster Configuration --------------"
                table_columns = ["Name","Master VIP","VIP Interface","Services CIDR","Containers CIDR","MetalLB Range"]
                table_rows = [
                    [
                        action['cluster']['name'],
                        action['cluster']['master_vip_ipv4'],
                        action['cluster']['master_vip_iface'],
                        action['cluster']['services_cidr'],
                        action['cluster']['containers_cidr'],
                        action['cluster']['metallb_cidr']
                    ]
                ]
                reports.display_table(table_title, table_columns, table_rows)

                table_title = "\n-------------- Kubernetes Cluster Nodes --------------"
                table_columns = ["Hostname","Node Type","Node IP","Public IP"]
                table_rows = []
                for node in node_list:
                    node_entry = [
                        node['hostname'], 
                        node['node_type'], 
                        node['node_ip'],
                        node['public_ip'] 
                    ]
                    table_rows.append(node_entry)
                reports.display_table(table_title, table_columns, table_rows)

                # assign ip address (node_ip) to Ethernet interface
                if not globals.flag_skip_launch and flag_launched:
                    sys.stdout.write("\n[Setting IP Address for K8s Backend - All Instances]\n")
                    self.set_batch_ip_address(instance_uuids, node_list, action['ssh_username'], action['ssh_key'])

                # build Kubernetes cluster on PMK
                pf9_cloud.onboard_cluster(
                    globals.ctx['platform9']['region_url'],
                    globals.ctx['platform9']['username'],
                    globals.ctx['platform9']['password'],
                    globals.ctx['platform9']['tenant'],
                    globals.ctx['platform9']['region'],
                    action['cluster'],
                    node_list,
                    action['ssh_username'],
                    action['ssh_key']
                )

    def get_plans(self):
        try:
            api_endpoint = "/projects/{}/plans".format(self.project_id)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            rest_response = requests.get("{}/{}".format(globals.API_BASEURL,api_endpoint), verify=False, headers=headers)
            if rest_response.status_code == 200:
                try:
                    json_response = json.loads(rest_response.text)
                    return(json_response)
                except:
                    return(None)
        except:
            return(None)

        return(None)


    def show_plans(self):
        # query packet API
        plans = self.get_plans()

        # initialize table for report
        from prettytable import PrettyTable
        tmp_table = PrettyTable()
        tmp_table.title = "Plans"
        tmp_table.field_names = ["Name","Class","Price","Memory","CPU","NIC","Storage"]
        tmp_table.align["Name"] = "l"
        tmp_table.align["Class"] = "l"
        tmp_table.align["Price"] = "l"
        tmp_table.align["Memory"] = "l"
        tmp_table.align["CPU"] = "l"
        tmp_table.align["NIC"] = "l"
        tmp_table.align["Storage"] = "l"

        for plan in plans['plans']:
            plan_memory = "-"
            plan_nic = "-"
            plan_disk = "-"
            plan_cpu = "-"
            for s in plan['specs']:
                if s == 'memory':
                    plan_memory = plan['specs'][s]['total']
                if s == 'cpus':
                    num_cpu = 0
                    cpu_type = "-"
                    for cpu in plan['specs'][s]:
                        cpu_type = plan['specs'][s][num_cpu]['type']
                        num_cpu += 1
                    plan_cpu = "({}) {}".format(num_cpu, cpu_type)
                if s == 'nics':
                    num_nic = 0
                    nic_type = "-"
                    for nic in plan['specs'][s]:
                        nic_type = plan['specs'][s][num_nic]['type']
                        num_nic += 1
                    plan_nic = "({}) {}".format(num_nic, nic_type)
                if s == 'drives':
                    num_disk = 0
                    disk_type = "-"
                    for disk in plan['specs'][s]:
                        disk_type = plan['specs'][s][num_disk]['type']
                        num_disk += 1
                    plan_disk = "({}) {}".format(num_disk, disk_type)
            plan_name = plan['name']
            plan_class = plan['class']
            plan_price = plan['pricing']['hour']
            tmp_table.add_row([plan_name,plan_class,plan_price,plan_memory,plan_cpu,plan_nic,plan_disk])

        sys.stdout.write("------ {} ------\n".format(tmp_table.title))
        print(tmp_table)


    def get_oses(self):
        try:
            api_endpoint = "/operating-systems"
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            rest_response = requests.get("{}/{}".format(globals.API_BASEURL,api_endpoint), verify=False, headers=headers)
            if rest_response.status_code == 200:
                try:
                    json_response = json.loads(rest_response.text)
                    return(json_response)
                except:
                    return(None)
        except:
            return(None)

        return(None)


    def show_operating_systems(self):
        # query packet API
        oses = self.get_oses()

        # initialize table for report
        from prettytable import PrettyTable
        tmp_table = PrettyTable()
        tmp_table.title = "Operating Systems"
        tmp_table.field_names = ["Name","Slug","Distro","Version","Preinstallable","Licensed"]
        for tmp_field in tmp_table.field_names:
            tmp_table.align[tmp_field] = "l"

        for os in oses['operating_systems']:
            tmp_table.add_row([os['name'],os['slug'],os['distro'],os['version'],os['preinstallable'],os['licensed']])

        sys.stdout.write("------ {} ------\n".format(tmp_table.title))
        print(tmp_table)


    def get_facilities(self):
        try:
            api_endpoint = "/facilities"
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            rest_response = requests.get("{}/{}".format(globals.API_BASEURL,api_endpoint), verify=False, headers=headers)
            if rest_response.status_code == 200:
                try:
                    json_response = json.loads(rest_response.text)
                    return(json_response)
                except:
                    return(None)
        except:
            return(None)

        return(None)


    def show_facilities(self):
        # query packet API
        facilities = self.get_facilities()

        # initialize table for report
        from prettytable import PrettyTable
        tmp_table = PrettyTable()
        tmp_table.title = "Data Centers"
        tmp_table.field_names = ["Name","Code","UUID"]
        for tmp_field in tmp_table.field_names:
            tmp_table.align[tmp_field] = "l"

        for facility in facilities['facilities']:
            tmp_table.add_row([facility['name'],facility['code'],facility['id']])

        sys.stdout.write("------ {} ------\n".format(tmp_table.title))
        print(tmp_table)


    def get_devices(self):
        try:
            api_endpoint = "/projects/{}/devices".format(self.project_id)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            rest_response = requests.get("{}/{}".format(globals.API_BASEURL,api_endpoint), verify=False, headers=headers)
            if rest_response.status_code == 200:
                try:
                    json_response = json.loads(rest_response.text)
                    return(json_response)
                except:
                    return(None)
        except:
            return(None)

        return(None)


    def show_devices(self, filter_uuid_list=None):
        # query packet API
        devices = self.get_devices()

        # initialize table for report
        from prettytable import PrettyTable
        tmp_table = PrettyTable()
        tmp_table.title = "Bare-Metal Instances"
        tmp_table.field_names = ["Facility","Hostname","State","Operating System","Volumes","Storage","IP Addresses","Created/UUID"]
        for tmp_field in tmp_table.field_names:
            tmp_table.align[tmp_field] = "l"

        for d in devices['devices']:
            if filter_uuid_list and (not d['id'] in filter_uuid_list):
                continue

            facility_name = "{} (uuid={})".format(d['facility']['name'],d['facility']['code'])
            creation_info = "{}\n{}".format(d['created_at'],d['id'])
            ip_addrs = None
            for i in d['ip_addresses']:
                if ip_addrs:
                    ip_addrs = "{}\n{}".format(ip_addrs,i['address'])
                else:
                    ip_addrs = "{}".format(i['address'])
              
            tmp_table.add_row([facility_name,d['hostname'],d['state'],d['operating_system']['name'],d['volumes'],d['storage'],ip_addrs,creation_info])

        sys.stdout.write("------ {} ------\n".format(tmp_table.title))
        print(tmp_table)


    def get_device_uuid(self, hostname):
        # query packet API
        devices = self.get_devices()
        for d in devices['devices']:
            if d['hostname'] == hostname:
                return(d['id'])

        return(None)


    def get_public_ip(self, hostname, network_tag=None):
        # query packet API
        devices = self.get_devices()
        for d in devices['devices']:
            if d['hostname'] != hostname:
                continue
            for i in d['ip_addresses']:
                if i['address_family'] == 4 and i['public']:
                    return(i['address'])
                    
        return(None)


    def get_device_record(self, uuid):
        # query packet API
        try:
            api_endpoint = "/devices/{}".format(uuid)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            rest_response = requests.get("{}/{}".format(globals.API_BASEURL,api_endpoint), verify=False, headers=headers)
            if rest_response.status_code == 200:
                try:
                    json_response = json.loads(rest_response.text)
                    return(json_response)
                except:
                    return(None)
        except:
            return(None)

        return(None)


    def get_private_ip(self, hostname):
        # query packet API
        devices = self.get_devices()
        for d in devices['devices']:
            if d['hostname'] != hostname:
                continue
            for i in d['ip_addresses']:
                if i['address_family'] == 4 and not i['public']:
                    return(i['address'])

        return(None)


    def get_instance_status(self, instance_uuid):
        instance_state = "inactive"
        try:
            api_endpoint = "/devices/{}".format(instance_uuid)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            rest_response = requests.get("{}/{}".format(globals.API_BASEURL,api_endpoint), verify=False, headers=headers)
            if rest_response.status_code == 200:
                try:
                    json_response = json.loads(rest_response.text)
                    return(json_response['state'])
                except:
                    return(instance_state)
        except Exception as ex:
            return(instance_state)

        return(instance_state)


    def delete_instance(self, uuid):
        try:
            api_endpoint = "/devices/{}".format(uuid)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            rest_response = requests.delete("{}/{}".format(globals.API_BASEURL,api_endpoint), verify=False, headers=headers)
            if rest_response.status_code == 204:
                return(True)
        except:
            return(False)

        return(False)


    def get_virtual_networks(self):
        try:
            api_endpoint = "projects/{}/virtual-networks".format(self.project_id)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            rest_response = requests.get("{}/{}".format(globals.API_BASEURL,api_endpoint), verify=False, headers=headers)
            if rest_response.status_code != 200:
                return(None)
        except Exception as ex:
            sys.stdout.write("ERROR: failed (exception.message={})\n".format(ex.message))
            return(None)

        # parse rest response
        try:
            json_response = json.loads(rest_response.text)
            return(json_response)
        except Exception as ex1:
            sys.stdout.write("ERROR: {}\n".format(ex1.message))
            return(None)


    def disable_port(self, server_record):
        # validate server record
        required_keys = ['name','id','data','type','bond','native_virtual_network','hardware','connected_port','href','network_ports']
        for key_name in required_keys:
            if not key_name in required_keys:
                sys.stdout.write("ERROR: missing required key in action: {}\n".format(key_name))
                return(None)

        # parse server record for post data
        for tmp_port in server_record['network_ports']:
            if tmp_port['name'] == "eth1":
                port_id = tmp_port['id']
                port_name = tmp_port['name']
                port_mac = tmp_port['data']['mac']
                port_type = tmp_port['type']
                port_bond = tmp_port['bond']
                port_native_virtual_network = tmp_port['native_virtual_network']
                port_hardware = tmp_port['hardware']
                port_connented_to = tmp_port['connected_port']
                port_href = tmp_port['href']

        # configure post data
        post_payload = {
            "id": port_id,
            "type": port_type,
            "name": port_name,
            "data": { 
                "bonded": False,
                "mac": port_mac
            },
            "bond": port_bond,
            "native_virtual_network": port_native_virtual_network,
            "hardware": port_hardware,
            "virtual_networks": [],
            "connected_port": port_connented_to,
            "href": port_href
        }

        # perform post operation
        sys.stdout.write("--> disabling port (id={})\n".format(port_id))
        try:
            api_endpoint = "ports/{}/disbond".format(port_id)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            rest_response = requests.post("{}/{}".format(globals.API_BASEURL,api_endpoint), verify=False, headers=headers, data=json.dumps(post_payload))
            if rest_response.status_code != 200:
                sys.stdout.write("ERROR: got enexpected http response code: {}\n".format(rest_response.status_code))
                return(None)
        except Exception as ex:
            sys.stdout.write("ERROR: failed to disable port (exception.message={})\n".format(ex.message))
            return(None)

        # parse rest response
        try:
            json_response = json.loads(rest_response.text)
            return(json_response)
        except Exception as ex1:
            sys.stdout.write("INFO: failed to disable port (exception.message={})\n".format(ex1.message))
            return(None)


    def assign_vlan(self, server_record, vlan_tag):
        # search for vlan with description = vlan_tag)
        vlan_record = []
        virtual_networks = self.get_virtual_networks()
        if virtual_networks:
            for vlan in virtual_networks['virtual_networks']:
                if vlan['description'] == vlan_tag:
                    vlan_record.append(vlan)
        if len(vlan_record) == 0:
            return(None)

        # validate server record
        required_keys = ['name','id','data','type','bond','native_virtual_network','hardware','connected_port','href','network_ports']
        for key_name in required_keys:
            if not key_name in required_keys:
                sys.stdout.write("ERROR: missing required key in action: {}\n".format(key_name))
                return(None)

        # parse server record for post data
        for tmp_port in server_record['network_ports']:
            if tmp_port['name'] == "eth1":
                port_id = tmp_port['id']
                port_name = tmp_port['name']

        # configure post data
        post_payload = {
            "id": port_id,
            "vnid": vlan_record[0]['id']
        }

        # perform post operation
        sys.stdout.write("--> assigning port {} to VLAN (id={})\n".format(port_name, vlan_record[0]['vxlan']))
        try:
            api_endpoint = "ports/{}/assign".format(port_id)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            rest_response = requests.post("{}/{}".format(globals.API_BASEURL,api_endpoint), verify=False, headers=headers, data=json.dumps(post_payload))
            if rest_response.status_code != 200:
                sys.stdout.write("ERROR: got enexpected http response code: {}\n".format(rest_response.status_code))
                return(None)
            return(rest_response.text)
        except Exception as ex:
            sys.stdout.write("ERROR: failed to set VLAN (exception.message={})\n".format(ex.message))
            return(None)

        return(None)


    def set_hybrid_mode(self, instance_uuid):
        return(None)

    def assign_batch_vlan(self, instance_uuids, vlan_tag):
        for uuid in instance_uuids:
            server_record = self.get_device_record(uuid)
            if server_record:
                vlan_result = self.assign_vlan(server_record, vlan_tag)
                if vlan_result:
                    return(True)
                else:
                    sys.stdout.write("ERROR: failed to assign VLAN to {}\n".format(server_record['hostname']))
  
        return(False)


    def set_batch_ip_address(self, instance_uuids, node_list, ssh_user, ssh_key):
        for uuid in instance_uuids:
            server_record = self.get_device_record(uuid)
            if server_record:
                for node in node_list:
                    if node['hostname'] == server_record['hostname']:
                        sys.stdout.write("--> {}: setting IP for {} to {}/{}\n".format(server_record['hostname'],node['node_ip_interface'],node['node_ip'], node['node_ip_mask']))
                        cmd = "ifconfig {} {} netmask {} up".format(node['node_ip_interface'], node['node_ip'],node['node_ip_mask'])
                        ssh_utils.run_cmd_ssh(node['public_ip'], ssh_user, ssh_key, cmd)
  
        return(True)


    def set_batch_hybrid_mode(self, instance_uuids):
        for uuid in instance_uuids:
            server_record = self.get_device_record(uuid)
            if server_record:
                port_result = self.disable_port(server_record)
                if not port_result:
                    sys.stdout.write("ERROR: {}: failed to disable port\n".format(server_record['hostname']))
  
        return(True)


    def dump_device_record(self, uuid):
        import pprint 

        device_record = self.get_device_record(uuid)
        if not device_record:
            sys.stdout.write("ERROR: device not found\n")
            return()
  
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(device_record)


