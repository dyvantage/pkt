# PKT | CLI for deploying Kubernetes clusters on Packet.net
PKT launches bare-metal instances on [Packet.Net](https://app.packet.net) and optionally orchestrate the installation of a production-quality Kubernetes cluster.

## Installation (Public URL)
PKT is written in Python and installs with PIP.  The installer (written in Bash) sets up a Python virtual environment, clones the PKT repo on Github, and uses PIP to install PKT into the virtual environment.

To install PKT, run the following command from a Bash shell prompt:
```
/bin/bash <(curl -s https://raw.githubusercontent.com/dwrightco1/pkt/master/pkt)
```
Here's a sample installation:
```
$ /bin/bash <(curl -s https://raw.githubusercontent.com/dwrightco1/pkt/master/pkt)
Running on: ubuntu 16.04
Logging to: /home/cmadmin/pkt.log
Initializing Virtual Environment using Python 3
--> Installing Pip
--> Installing python package: virtualenv
--> Starting virtual environment (located in /home/cmadmin/.packet/venv)
--> Upgrading Pip

Downloading PKT
--> Cloning into /home/cmadmin/pkt (sourcing from: https://github.com/dwrightco1/pkt.git)
--> Installing PKT

PKT Installation Complete, to start run:
source /home/cmadmin/.packet/venv/bin/activate && pkt
```
NOTE: To re-init the installation, add the '-i' option:

## Configuring PKT
The first time you invoke PKT (or whenever ~/pkt.conf does not exist) it will prompt you for your Packet.Net & Platform9 credentials:
```
ubuntu-xenial:~$ source /home/cmadmin/.packet/venv/bin/activate && pkt

██████╗ ██╗  ██╗████████╗
██╔══██╗██║ ██╔╝╚══██╔══╝
██████╔╝█████╔╝    ██║
██╔═══╝ ██╔═██╗    ██║
██║     ██║  ██╗   ██║
╚═╝     ╚═╝  ╚═╝   ╚═╝

Welcome to PKT!
Run: 'pkt -h' for usage information

Please enter credentials for Packet.Net:
--> Project ID []: <your-project-id>
--> API Key: <your-api-key>

Please enter credentials for Platform9.Com:
--> PMK Region URL []: <your-region-url>
--> Username []: <your-username>
--> Password: <your-password>
--> Tenant [service]:
--> Region Name [RegionOne]:
--> Express-CLI Branch [master]:
```
Once configuration is complete, you can immediately start querying Packet, lauching instances, and building Kubernetes clusters.

## Supported Operating Systems
PKT is tested on MacOS-10, Ubuntu-16, and CentOS-7.  The installer will fail if an unsuppoted OS is detected.

NOTE: Support for CentOS-8 and Ubuntu-18 is in-progress.

## Kubernetes Integration
PKT uses [Express-CLI](https://github.com/platform9/express-cli) to deploy Kubernetes on bare-metal [Packet.Net](https://app.packet.net) instances using [Platform9 PMK](https://platform9.com/signup)

## Kubernetes Cluster Deployment
A cluster is deployed by running `pkt --apply <spec-file>`

The `<spec-file>` is used to describe the details of the Packet bare-metal instances (to be used as Kubernetes cluster nodes), the credentials for the Platform9 SaaS control plane, as well as the details of the Kubernetes cluster.

*To launch bare-metal instances on Packet.Net and use them as cluster nodes, use a `<spec-file>` that looks like this:*
```
{
  "actions": [
      {
          "operation": "launch-instance",
          "num_instances": 1,
          "hostname_base": "<hostname-base> (note: will be appended with '01', '02', etc.)",
          "plan": "<planName>",
          "facility": "<facilityName>",
          "operating_system": "<osName>",
          "userdata": "",
          "customdata": "",
          "network_mode": "<layer3|hybrid>",
          "k8s_vlan_tag": "<descr-on-vlan> (note: place this text in the 'Description' field of the VLAN)",
          "ip_addresses": [
              {
                  "address_family": 4,
                  "public": false
              },
              {
                  "address_family": 4,
                  "public": true
              },
              {
                  "address_family": 6,
                  "public":true
              }
          ]
      },
      {
          "operation": "pf9-build-cluster",
          "pmk_region": {
            "url": "<region-url>",
            "username": "<region-username>",
            "password": "<region-password> (note: must be encrypted using 'pkt -e')",
            "tenant": "<region-tenant>",
            "region": "<region-name>"
          },
          "ssh_username" : "<username-for-ssh-access>",
          "ssh_key" : "<path-to-ssh-privateKey>",
          "cluster": {
            "name": "<cluster-name>",
            "master_vip_ipv4": "<vip-ip>",
            "master_vip_iface": "<vip-interfaceName>",
            "metallb_cidr": "<startIp>-<endIp>",
            "containers_cidr": "192.168.0.0/16",
            "services_cidr": "192.169.0.0/16",
            "privileged": 0,
            "app_catalog_enabled": 0,
            "allow_workloads_on_master": 0
          }
      }
  ]
}
```

*Using Existing Servers (as cluster nodes)*
If you want to use existing servers (i.e. skip launching the instances on Packet, and instead use whetever servers/instances you want, use a `<spec-file>` that looks like this:
```
{
  "actions": [
      {
          "operation": "imported-instances",
          "instances": {
              "k8s01": "10.238.0.15"
          }
      },
      {
          "operation": "pf9-build-cluster",
          "ssh_username" : "cmadmin",
          "ssh_key" : "~/env-setup/macs/imac01/keys/cm-master",
          "masters": [
              { "hostname": "k8s01", "node_ip": "10.0.2.15", "node_ip_mask": "255.255.255.0", "interface": "enp0s3" }
          ],
          "workers": [
          ],
          "k8s_network_tag": "k8s-backend01",
          "cluster": {
            "name": "pkt03",
            "master_vip_ipv4": "10.0.2.200",
            "master_vip_iface": "enp0s3",
            "metallb_cidr": "10.0.2.201-10.0.2.250",
            "containers_cidr": "192.168.0.0/16",
            "services_cidr": "192.169.0.0/16",
            "privileged": 1,
            "app_catalog_enabled": 0,
            "allow_workloads_on_master": 0
          }
      }
  ]
}
```

## Sample Run
Here is the log from a 3x2 cluster build (3 masters, 2 workers):
```
$ pkt --apply conf/k8s-cluster-3x2.json
-------------- Action Parameters --------------
+-----------------+---------------+-------------+------------------+---------------+-------------+
| Operation Type  | Plan          | Data Center | Operating System | Hostname Base | # Instances |
+-----------------+---------------+-------------+------------------+---------------+-------------+
| launch-instance | c2.medium.x86 | sjc1        | ubuntu_16_04     | k8s           | 5           |
+-----------------+---------------+-------------+------------------+---------------+-------------+

[Launching Instances]
--> skipping (globals.flag_skip_launch = True)
--> skipping (globals.flag_skip_launch = True)
--> skipping (globals.flag_skip_launch = True)
--> skipping (globals.flag_skip_launch = True)
--> skipping (globals.flag_skip_launch = True)

[Waiting for All Instances to Boot]
--> all instances booted successfully, boot time = 468 seconds

------ Bare-Metal Instances ------
+---------------------------+----------+--------+------------------+---------+---------+----------------+--------------------------------------+
| Facility                  | Hostname | State  | Operating System | Volumes | Storage | IP Addresses   | Created/UUID                         |
+---------------------------+----------+--------+------------------+---------+---------+----------------+--------------------------------------+
| Sunnyvale, CA (uuid=sjc1) | k8s02    | active | Ubuntu 16.04 LTS | []      | {}      | 147.75.49.250  | 2020-04-14T20:24:28Z                 |
|                           |          |        |                  |         |         | 10.88.91.3     | db006d87-7276-4916-8913-834d04b21b4c |
| Sunnyvale, CA (uuid=sjc1) | k8s03    | active | Ubuntu 16.04 LTS | []      | {}      | 147.75.49.99   | 2020-04-14T20:24:46Z                 |
|                           |          |        |                  |         |         | 10.88.91.5     | a1df33be-c330-4de7-844b-4ca0b7be53f5 |
| Sunnyvale, CA (uuid=sjc1) | k8s01    | active | Ubuntu 16.04 LTS | []      | {}      | 147.75.49.194  | 2020-04-14T20:24:10Z                 |
|                           |          |        |                  |         |         | 10.88.91.1     | 3534494f-6a0f-48cb-b9b7-ab9b738b89d9 |
| Sunnyvale, CA (uuid=sjc1) | k8s05    | active | Ubuntu 16.04 LTS | []      | {}      | 147.75.109.127 | 2020-04-14T20:25:21Z                 |
|                           |          |        |                  |         |         | 10.88.91.9     | 1b30fed6-9c21-4a83-9d93-496e183bae2a |
| Sunnyvale, CA (uuid=sjc1) | k8s04    | active | Ubuntu 16.04 LTS | []      | {}      | 147.75.49.199  | 2020-04-14T20:25:04Z                 |
|                           |          |        |                  |         |         | 10.88.91.7     | 7edfd12d-3b3e-44d3-b9f6-470ad9a4f04f |
+---------------------------+----------+--------+------------------+---------+---------+----------------+--------------------------------------+

[Initializing PMK Integration]
--> logged into PMK region: https://pmkft-1581453652-84909.platform9.io/ (user=dwrightco1@gmail.com/tenant=service)

-------------- Kubernetes Cluster Configuration --------------
+-------+-----------------+---------------+----------------+-----------------+---------------------------------+
| Name  | Master VIP      | VIP Interface | Services CIDR  | Containers CIDR | MetalLB Range                   |
+-------+-----------------+---------------+----------------+-----------------+---------------------------------+
| pkt01 | 192.167.100.200 | enp1s0f1      | 192.169.0.0/16 | 192.168.0.0/16  | 192.167.100.201-192.167.100.254 |
+-------+-----------------+---------------+----------------+-----------------+---------------------------------+

-------------- Kubernetes Cluster Nodes --------------
+----------+-----------+------------+----------------+
| Hostname | Node Type | Node IP    | Public IP      |
+----------+-----------+------------+----------------+
| k8s01    | master    | 172.16.0.1 | 147.75.49.194  |
| k8s02    | master    | 172.16.0.2 | 147.75.49.250  |
| k8s03    | master    | 172.16.0.3 | 147.75.49.99   |
| k8s04    | worker    | 172.16.0.4 | 147.75.49.199  |
| k8s05    | worker    | 172.16.0.5 | 147.75.109.127 |
+----------+-----------+------------+----------------+

[Initialize Express-CLI (branch = tomchris/restructure)]
--> refreshing repository (git fetch -a)
--> current branch: tomchris/restructure
--> target branch: tomchris/restructure
--> pulling latest code (git pull origin tomchris/restructure)
--> pip installing express-cli
--> building configuration file

[Invoking Express-CLI (to orchestrate cluster provisioning)]
--> running: express cluster create -u root -s ~/.ssh/id_rsa -m 172.16.0.1 -f 147.75.49.194 -m 172.16.0.2 -f 147.75.49.250 -m 172.16.0.3 -f 147.75.49.99 -w 172.16.0.4 -f 147.75.49.199 -w 172.16.0.5 -f 147.75.109.127 --masterVip 192.167.100.200 --masterVipIf enp1s0f1 --metallbIpRange 192.167.100.201-192.167.100.254 --containersCidr 192.168.0.0/16 --servicesCidr 192.169.0.0/16 --privileged True --appCatalogEnabled False --allowWorkloadsOnMaster False pkt01

Creating Cluster: pkt01
Using nodepool id: 41caa389-a031-4c69-9aa9-3a06ff2745b5
Waiting for cluster create to complete, status = True
Cluster pkt01 created successfully
Cluster UUID: a5a89dbb-6db7-4d88-9631-1e35d409c838
Attaching to cluster pkt01
Discovering UUIDs for the cluster's master nodes
Master nodes:
Discovering UUIDs for the cluster's worker nodes
Worker Nodes:
Waiting for cluster create to complete, status = True
Attaching master nodes to the cluster
Waiting for cluster to become ready
Attaching to cluster
Successfully attached to cluster
Attaching worker nodes to the cluster
Waiting for cluster to become ready
Attaching to cluster
Successfully attached to cluster
Successfully created cluster pkt01 using node(s):
    masters: ('172.16.0.1', '172.16.0.2', '172.16.0.3')
    workers: ('172.16.0.4', '172.16.0.5')
```
