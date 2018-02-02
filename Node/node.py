import requests
from klein import Klein
import json
import random

from Structures.peoplechain import Peoplechain
from Structures.record import Record
from Structures.user import User
from Structures.key import Key
from Structures.organization import Organization
from Structures.mixin import NodeMixin

import socket

class FullNode(NodeMixin):

    NODE_TYPE = 'full'
    peoplechain = None
    app = Klein()

    def __init__(self, private_key=None): #TODO Raise mining request, approved by existing miners then can mine.

        if private_key is None:
            print ("Starting a new chain\n")
            print ("Generating Genesis User Key Pair")
            self.key = Key()
            print ("Generating Genesis User")
            print ("Network Key: {}".format(self.key.get_private_key()))
            #TODO: store the information in config file
            user = User(1000000000000001, self.key.get_public_key(), "genesis@peoplechain.org", '9c87399d78e6398e672c6da6ae8fe1ae66c194e767504371723e2ad65e288781', "Network", 'Genesis User - PCN', "Genesis User - PCN", "Bangalore")
            self.peoplechain = Peoplechain()
            self.peoplechain.add_user(user)
            print ("Peoplechain Created.")
            print (self.peoplechain.users)
        else:
            print ("Generating key pair from private key")
            self.key = Key(private_key)
            self.request_nodes_from_all()
            if not self.discover_user(self.key.get_public_key()):
                raise Exception()
            remote_chain = self.download()
            self.peoplechain = Peoplechain(remote_chain)
            self.node = self.get_my_node()
            self.broadcast_node(self.node)
            self.full_nodes.union([self.node])


        print ("\n -------------- Starting Full Node Server -------------- \n")
        self.app.run('0.0.0.0', self.FULL_NODE_PORT)

    def discover_user(self, address):

        bad_nodes = set()
        for node in self.full_nodes:
            url = self.USER_GET_URL.format(node, self.FULL_NODE_PORT, address)
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    return True
            except requests.exceptions.RequestException as re:
                bad_nodes.add(node)

        for node in bad_nodes:
            self.remove_node(node)
        bad_nodes.clear()
        return False

    def download(self):

        for node in self.full_nodes:
            url = self.CHAIN_URL.format(node, self.FULL_NODE_PORT)
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    return response.json()
            except requests.exceptions.RequestException as re:
                pass

    def get_my_node(self):
        my_node = requests.get('https://api.ipify.org').text
        return my_node

    def broadcast_node(self, node):
        bad_nodes = set()
        data = {
            "host": node
        }
        for node in self.full_nodes:
            url = self.NODES_URL.format(node, self.FULL_NODE_PORT)
            try:
                requests.post(url, json=data)
            except requests.exceptions.RequestException as re:
                bad_nodes.add(node)

        for node in bad_nodes:
            self.remove_node(node)
        bad_nodes.clear()
        return

    @app.route('/record', methods=['POST'])
    def add_record(self, request):
        record_data = json.loads(request.content.read().decode('utf-8'))
        record_json = json.loads(record_data['record'])
        record = Record.from_json(record_json)
        if record.signature is None:
            self.peoplechain.add_unconfirmed_record(record)
            return
        else:
            self.peoplechain.record_signed(record)
            #payment_record = Record(record.endorser, record.endorsee, "Payment for Signing", 2, record.hash)
            #self.peoplechain.add_record_to_user(payment_record) #TODO: verify this record.signature == this.record.endorser.somerecord.hash
            return

    @app.route('/record/<address>', methods=['GET'])
    def get_all_unconfirmed_transactions(self, request, address):
        urecords = self.peoplechain.get_unconfirmed_records(address)
        data = {
            "records": urecords
        }
        return json.dumps(data).encode('utf-8')

    @app.route('/organization', methods=['POST'])
    def create_organization(self, request):
        org_data = json.loads(request.content.read().decode('utf-8'))
        org_json = json.loads(org_data['organization'])
        organization = Organization.from_json(org_json)
        self.peoplechain.add_organization(organization)
        response = {
            "message": "Organization Created"
        }
        return json.dumps(response).encode('utf-8')

    @app.route('/organization/all', methods=['GET'])
    def get_all_organization_on_node(self, request):
        if len(self.peoplechain.organizations) > 0:
            data = {
                "organizations": [orgainzation.to_json() for organization in self.peoplechain.organizations]
            }
            return json.dumps(data)
        return None    

    @app.route('/user', methods=['POST'])
    def create_user(self, request):
        user_data = json.loads(request.content.read().decode('utf-8'))
        user_json = json.loads(user_data['user'])
        print (type(user_json))
        user = User.from_json(user_json)
        self.peoplechain.add_user(user)
        response = {
            "message": "User Profile created"
        }
        return json.dumps(response).encode('utf-8')

    @app.route('/user', methods=['GET'])
    def get_all_user_address(self, request):

        data = {
            "users": [user.address for user in self.peoplechain.users]
        }

        return json.dumps(data).encode('utf-8')

    @app.route('/user/<address>', methods=['GET'])
    def get_user_by_address(self, request, address):
        user = self.peoplechain.get_user_by_address(address)
        if user is not None:
            data = {
                "user": user.to_json()
            }
            return json.dumps(data).encode('utf-8')
        else:
            return

    @app.route('/user/email/<email>', methods=['GET'])
    def get_user_by_email(self, request, email):
        user = self.peoplechain.get_user_by_email(email)
        if user is not None:
            data = {
                "user": user.to_json()
            }
            return json.dumps(data).encode('utf-8')
        else:
            return

    @app.route('/user/index', methods=['GET'])
    def get_latest_user_index(self, request):
        return str(self.peoplechain.get_latest_user_index())

    @app.route('/user/index/<index>', methods=['GET'])
    def get_user_by_index(self, request, index):
        user = self.peoplechain.get_user_by_index(index)
        print (user)
        if user is not None:
            data = {
                "user": user.to_json()
            }
            return json.dumps(data).encode('utf-8')
        else:
            return

    @app.route('/orgainzation/index', methods=['GET'])
    def get_latest_organization_index(self, request):
        return str(self.peoplechain.get_latest_organization_index())

    @app.route('/organization/<address>', methods=['GET'])
    def get_organization_by_admin(self, request, address):
        organization = self.peoplechain.get_organization_by_admin(address)
        if organization is not None:
            data = {
                "organization": organization.to_json()
            }
            return json.dumps(data).encode('utf-8')
        else:
            return

    @app.route('/organization/index/<index>', methods=['GET'])
    def get_organization_by_index(self, request, index):
        organization = self.peoplechain.get_organization_by_index(index)
        if organization is not None:
            data = {
                "organization": organization.to_json()
            }
            return json.dumps(data).encode('utf-8')
        else:
            return

    @app.route('/organization/admin/add', methods=['POST'])
    def add_admin(self, request):
        body = json.loads(request.content.read().decode('utf-8'))
        admin = body['admin']
        index = body['index']
        self.peoplechain.add_organization_admin(index, admin)
        return

    @app.route('/nodes', methods=['GET'])
    def get_nodes(self, request):
        response = {
            "full_nodes": list(self.full_nodes)
        }
        return json.dumps(response).encode('utf-8')

    @app.route('/nodes', methods=['POST'])
    def post_node(self, request):
        body = json.loads(request.content.read().decode('utf-8'))
        host = body['host']
        self.full_nodes.add(host)
        response = {
            "message": "Node Registered"
        }
        return json.dumps(response).encode('utf-8')

    @app.route('/chain', methods=['GET'])
    def get_chain(self, request):
        data = {
            "users": [user.to_json() for user in self.peoplechain.users],
            "unconfirmed_records": [ur.to_json() for ur in self.peoplechain.unconfirmed_records],
            "organizations": [organization.to_json() for organization in self.peoplechain.organizations]
        }
        return json.dumps(data).encode('utf-8')

    @app.route('/balance/<address>', methods=['GET'])
    def get_balance(self, request, address):
        return str(self.peoplechain.get_balance(address))

    @app.route('/genesis', methods=['GET'])
    def get_genesis_user_address(self, request):
        return self.peoplechain.get_genesis_user_address()

if __name__ == '__main__':
    private_key = str(input('Enter private key, leave blank for new chain'))
    if private_key == '':
        node = FullNode()
    else:
        node = FullNode(private_key)
