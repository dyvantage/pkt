import sys
import requests
import json
import express_cli
import globals

class PMK:
    def __init__(self, du_url, du_user, du_password, du_tenant):
        self.du_url = du_url
        self.du_user = du_user
        self.du_password = du_password
        self.du_tenant = du_tenant
        self.project_id, self.token = self.login()
        

    def validate_login(self):
        if not self.token:
            return(False)
        else:
            return(True)

    def login(self):
        url = "{}/keystone/v3/auth/tokens?nocatalog".format(self.du_url)
        body = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": { "name": self.du_user, "domain": {"id": "default"}, "password": self.du_password }
                    }
                },
                "scope": {
                    "project": {
                        "name": self.du_tenant, "domain": {"id": "default"}
                    }
                }
            }
        }

        # attempt to login to region
        try:
            resp = requests.post(url, data=json.dumps(body), headers={'content-type': 'application/json'}, verify=False)
            json_response = json.loads(resp.text)
        except:
            return(None, None)

        # check for login failure
        if not "token" in json_response:
            return(None, None)

        return(json_response['token']['project']['id'], resp.headers['X-Subject-Token'])


    def onboard_cluster(self, url, username, password, tenant, region, cluster, nodes, ssh_username, ssh_key):
        # initialize express-cli (required for Platform9 integration)
        if not express_cli.init(globals.ctx['platform9']['region_url'], globals.ctx['platform9']['username'], globals.ctx['platform9']['password'], globals.ctx['platform9']['tenant'], globals.ctx['platform9']['region']):
            sys.exit(1)

        if not express_cli.build_cluster(cluster, nodes, ssh_username, ssh_key):
            sys.exit(1)


    def download_kubeconfig(self, cluster_uuid):
        sys.stdout.write("\n[Downloading Kubeconfig]\n")
        try:
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            api_endpoint = "qbert/v3/{}/kubeconfig/{}".format(self.project_id, cluster_uuid)
            rest_response = requests.get("{}/{}".format(self.du_url, api_endpoint), verify=False, headers=headers)
            if rest_response.status_code != 200:
                sys.stdout.write("{}\n".format(rest_response.text))
                return False
        except:
            return False

        # write kubeconfig to file
        data_file = "{}/kubeconfig".format(globals.INSTALL_DIR)
        try:
            data_file_fh = open(data_file, "w")
            data_file_fh.write("{}".format(rest_response.text.replace('__INSERT_BEARER_TOKEN_HERE__',self.token)))
            data_file_fh.close()
        except:
            return False

        # validate uuid was written/persisted (to data_file)
        if not os.path.isfile(data_file):
            return False

        return data_file

