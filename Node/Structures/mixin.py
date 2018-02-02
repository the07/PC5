import json
import requests

class NodeMixin(object):

    full_nodes = set(['103.88.129.43']) #TODO move to a configuration file
    FULL_NODE_PORT = 30609
    NODES_URL = "http://{}:{}/nodes"
    CHAIN_URL = "http://{}:{}/chain"
    RECORD_URL = "http://{}:{}/record"
    URECORD_URL = "http://{}:{}/record/{}"
    USER_URL = "http://{}:{}/user"
    USER_INDEX_URL = "http://{}:{}/user/index/{}"
    BALANCE_URL = "http://{}:{}/balance/{}"
    USER_GET_URL = "http://{}:{}/user/{}"
    GENESIS_URL = "http://{}:{}/genesis"
    ORGANIZATION_URL = "http://{}:{}/organization"
    ORGANIZATION_GET_URL = "http://{}:{}/organization/{}"
    ORGANIZATION_GET_INDEX_URL = "http://{}:{}/organization/index/{}"

    def request_nodes(self, node):
        url = self.NODES_URL.format(node, self.FULL_NODE_PORT)
        try:
            response = requests.get(url)
            if response.status_code == 200:
                all_nodes = response.json()
                return all_nodes
        except requests.exceptions.RequestException as re:
            pass
        return None

    def request_nodes_from_all(self):
        full_nodes = self.full_nodes.copy()
        bad_nodes = set()

        for node in full_nodes:
            all_nodes = self.request_nodes(node)
            if all_nodes is not None:
                full_nodes = full_nodes.union(all_nodes["full_nodes"])
            else:
                bad_nodes.add(node)

        self.full_nodes = full_nodes

        for node in bad_nodes:
            self.remove_node(node)
        return

    def remove_node(self, node):
        pass

    def random_node(self):
        all_nodes = self.full_nodes.copy()
        node = random.sample(all_nodes, 1)[0]
        return node

    def broadcast_record(self, record):
        self.request_nodes_from_all()
        bad_nodes = set()
        data = {
            "record": record.to_json()
        }

        for node in self.full_nodes:
            url = self.RECORD_URL.format(node, self.FULL_NODE_PORT)
            try:
                response = requests.post(url, json=data)
            except requests.exceptions.RequestException as re:
                bad_nodes.add(node)

        for node in bad_nodes:
            self.remove_node(node)
        bad_nodes.clear()
        return
        #TODO: convert to grequests and return list of responses

    def broadcast_user(self, user):
        self.request_nodes_from_all()
        bad_nodes = set()
        data = {
            "user": user.to_json()
        }

        for node in self.full_nodes:
            url = self.USER_URL.format(node, self.FULL_NODE_PORT)
            try:
                response = requests.post(url, json=data)
            except requests.exceptions.RequestException as re:
                bad_nodes.add(node)

        for node in bad_nodes:
            self.remove_node(node)
        bad_nodes.clear()
        return

if __name__ == '__main__':
    pass
