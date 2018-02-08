from klein import Klein
import random
import requests
from twisted.web.static import File
import json
from bs4 import BeautifulSoup
from hashlib import sha256

from Structures.key import Key
from Structures.user import User
from Structures.organization import Organization
from Structures.record import Record
from Structures.mixin import NodeMixin

CLIENT_ID = '81vdhr329qj4k6'
CLIENT_SECRET = 'uyi0DCDgIIGGdI0P'

class Instance:

    def __init__(self, session_id, user):

        self.__session_id__ = session_id
        self.__user__ = user

    @property
    def session_id(self):
        return self.__session_id__

    def get_user_by_session(self, session_id):
        if self.__session_id__ == session_id:
            return self.__user__

class Server(NodeMixin):

    app = Klein()
    CLIENT_PORT = 30906
    instances = []

    def __init__(self):

        self.app.run('0.0.0.0', self.CLIENT_PORT)

    def get_latest_user_index(self):
        self.request_nodes_from_all()
        for node in self.full_nodes:
            url = self.LATEST_USER_INDEX_URL.format(node, self.FULL_NODE_PORT)
            try:
                response = requests.get(url)
                return int(response.content)
            except requests.exceptions.RequestException as re:
                pass

    def get_user_by_email(self, email):
        self.request_nodes_from_all()
        for node in self.full_nodes:
            url = self.USER_EMAIL_URL.format(node, self.FULL_NODE_PORT, email)
            try:
                response = requests.get(url)
                response_content = response.content.decode('utf-8')
                if response_content is not '':
                    user_json = json.loads(json.loads(response_content)['user'])
                    return User.from_json(user_json)
                else:
                    return None
            except requests.exceptions.RequestException as re:
                pass

    def get_user_by_index(self, index):
        self.request_nodes_from_all()
        for node in self.full_nodes:
            url = self.USER_INDEX_URL.format(node, self.FULL_NODE_PORT, index)
            try:
                response = requests.get(url)
                response_content = response.content.decode('utf-8')
                if response_content is not '':
                    user_json = json.loads(json.loads(response_content)['user'])
                    return User.from_json(user_json)
                else:
                    return None
            except requests.exceptions.RequestException as re:
                pass

    def get_all_organization(self):
        self.request_nodes_from_all()
        for node in self.full_nodes:
            url = self.ALL_ORGANIZATION_URL.format(node, self.FULL_NODE_PORT)
            organizations = []
            try:
                response = requests.get(url)
                if len(response.content.decode('utf-8')) == 0:
                    return None
                else:
                    response_content = json.loads(response.content.decode('utf-8'))
                    for organization in response_content['organizations']:
                        organization = Organization.from_json(json.loads(organization))
                        organizations.append(organization)
                    return organizations
            except requests.exceptions.RequestException as re:
                pass

    def get_latest_organization_index(self):
        self.request_nodes_from_all()
        for node in self.full_nodes:
            url = self.LATEST_ORGANIZATION_INDEX_URL.format(node, self.FULL_NODE_PORT)
            try:
                response = requests.get(url)
                response_content = response.content.decode('utf-8')
                return response_content
            except requests.exceptions.RequestException as re:
                pass

    def get_organization_by_admin(self, address):
        self.request_nodes_from_all()
        for node in self.full_nodes:
            url = self.ORGANIZATION_GET_URL.format(node, self.FULL_NODE_PORT, address)
            organizations = []
            try:
                response = requests.get(url)
                if response.content.decode('utf-8') == '0':
                    return None
                else:
                    response_content = json.loads(response.content.decode('utf-8'))
                    for organization in response_content['organizations']:
                        organization = Organization.from_json(json.loads(organization))
                        organizations.append(organization)
                    return organizations
            except requests.exceptions.RequestException as re:
                pass

    def get_genesis_user_address(self):
        self.request_nodes_from_all()
        for node in self.full_nodes:
            url = self.GENESIS_URL.format(node, self.FULL_NODE_PORT)
            try:
                response = requests.get(url)
                return response.content.decode('utf-8')
            except requests.exceptions.RequestException as re:
                pass

    def get_all_unconfirmed_records(self, address):
        self.request_nodes_from_all()
        for node in self.full_nodes:
            url = self.URECORD_URL.format(node, self.FULL_NODE_PORT, address)
            urecords = []
            try:
                response = requests.get(url)
                response_content = json.loads(response.content.decode('utf-8'))['records']
                if len(response_content) == 0:
                    return None
                for each in response_content:
                    record = Record.from_json(json.loads(each))
                    urecords.append(record)
                return urecords
            except requests.exceptions.RequestException as re:
                pass

    def add_admin_by_email(self, index, email):
        self.request_nodes_from_all()
        for node in self.full_nodes:
            url = self.ORGANIZATION_ADMIN_ADD_URL.format(node, self.FULL_NODE_PORT)
            data = {
                "index": index,
                "email": email
            }
            try:
                response = requests.post(url, json=data)
            except requests.exceptions.RequestException as re:
                pass
        return

    def get_balance(self, address):
        self.request_nodes_from_all()
        for node in self.full_nodes:
            url = self.BALANCE_URL.format(node, self.FULL_NODE_PORT, address)
            try:
                response = requests.get(url)
                balance = response.content.decode('utf-8')
                return balance
            except requests.exceptions.RequestException as re:
                pass


    @app.route('/', methods=['GET'], branch=True)
    def index(self, request):

        return File('./Frontend/')

    @app.route('/linkedin', methods=['GET'])
    def user_signup(self, request):

        if not request.args:
            message = "This place is on Mars, you need to be on Mars to access this."
            return json.dumps(message)

        # Link in html file to LinkedIn API returns access point
        authorization_code = request.args[b'code'][0].decode('utf-8')
        #TODO: check state

        # Prepare and access user profile
        url = 'https://www.linkedin.com/oauth/v2/accessToken'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': 'http://13.126.248.230:30906/linkedin',
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }

        r = requests.post(url=url, data=data, headers=headers)

        try:
            accessToken = json.loads(r.text)['access_token']
        except KeyError:
            message = 'Key Error, please login'
            return json.dumps(message)

        access_token_in_header = 'Bearer ' + accessToken

        user_url = 'https://api.linkedin.com/v1/people/~:(id,first-name,last-name,headline,location,summary,email-address)?format=json'
        user_url_headers = {'Connection': 'Keep-Alive', 'Authorization': access_token_in_header}
        s = requests.get(url=user_url, headers=user_url_headers)

        user_data =  json.loads(s.content.decode('utf-8'))

        html_file = open('Frontend/user-register.html').read()
        soup = BeautifulSoup(html_file, 'html.parser')

        soup.find("input", {"name":"name"})["value"] = user_data['firstName'] + ' ' + user_data['lastName']
        soup.find("input", {"name":"email"})["value"] = user_data['emailAddress']
        soup.find("input", {"name":"headline"})["value"] = user_data['headline']
        soup.find("textarea", {"name":"summary"}).insert(0, user_data['summary'])
        soup.find("input", {"name":"location"})["value"] = user_data['location']['name']

        return str(soup)

    @app.route('/register', methods=['POST'])
    def user_register(self, request):

        #Check if all values exist, do the same on the client side in a javascript file
        index = self.get_latest_user_index()
        # Generate a key pair
        key = Key()
        address = key.get_public_key()
        content = request.args

        #index, address, email, password, name, headline, summary, location,
        email = content[b'email'][0].decode('utf-8')
        password = content[b'password'][0]
        password_hash = sha256(password).hexdigest()
        name = content[b'name'][0].decode('utf-8')
        headline = content[b'headline'][0].decode('utf-8')
        summary = content[b'summary'][0].decode('utf-8')
        location = content[b'location'][0].decode('utf-8')
        user = User(index+1, address, email, password_hash, name, headline, summary, location)

        self.broadcast_user(user)

        html_file = open('Frontend/message.html').read()
        soup = BeautifulSoup(html_file, 'html.parser')
        message = "Your private Key: " + key.get_private_key() + ". Please save this in a secure location, you need this to sign records."
        soup.find(id='message').string = message
        new_a_tag = soup.new_tag('a')
        new_a_tag["href"] = "index.html"
        new_a_tag.string = "Login"
        soup.find(id='message').append(new_a_tag)
        return str(soup)

    @app.route('/login', methods=['POST'])
    def user_login(self, request):
        #Check if all values exist, do the same on the client side in a javascript file
        #Check if user exists with that username, if it does, check if the password matches
        #If both the username and password match, create a session, store user information in session, redirect to dashboard
        content = request.args
        email = content[b'email'][0].decode('utf-8')
        password = content[b'password'][0]
        print (email, password)
        password_hash = sha256(password).hexdigest()
        user = self.get_user_by_email(email)
        if user is None or user.password != password_hash:
            html_file = open('Frontend/index.html').read()
            soup = BeautifulSoup(html_file, 'html.parser')

            soup.find(id='message').string = "Incorrect email or password"
            return str(soup)
        if user.password == password_hash:
            session_id = request.getSession().uid.decode('utf-8')
            instance = Instance(session_id, user)
            self.instances.append(instance)
            request.redirect('/dashboard')

    @app.route('/dashboard', methods=['GET'])
    def user_dashboard(self, request):
        #From session get user
        #soup dashboard.html, give values, return soup
        session_id = request.getSession().uid.decode('utf-8')
        for instance in self.instances:
            if instance.session_id == session_id:
                user = instance.get_user_by_session(session_id)

                html_file = open('Frontend/dashboard.html').read()
                soup = BeautifulSoup(html_file, 'html.parser')

                source="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=" + "http://13.126.248.230:30906/view/" + user.index
                new_img_tag = soup.new_tag('img')
                new_img_tag['src'] = source
                soup.find(id='qr-image').append(new_img_tag)
                soup.find(id='uname').string = user.name
                soup.find(id='email').string = user.email
                soup.find(id='headline').string = user.headline
                soup.find(id='summary').string = user.summary
                soup.find(id='location').string = user.location

                work_tag = soup.find(id="working")
                education_tag = soup.find(id="study")
                other_tag = soup.find(id="other")
                unsigned_records = self.get_all_unconfirmed_records(user.address)

                organizations = self.get_all_organization()
                #users = self.get_all_users()

                for record in user.records:
                    record = Record.from_json(record)
                    new_div_tag = soup.new_tag("div")
                    new_div_tag["class"] = "callout"
                    role_tag = soup.new_tag("h5")
                    role_tag.string = record.role
                    new_div_tag.append(role_tag)
                    company_tag = soup.new_tag("h5")
                    company_tag.string = str(record.company)
                    new_div_tag.append(company_tag)
                    new_detail_tag = soup.new_tag("p")
                    new_detail_tag.string = record.detail
                    new_div_tag.append(new_detail_tag)
                    new_status_tag = soup.new_tag("p")
                    new_status_tag.string = "Signed: " + record.hash
                    new_div_tag.append(new_status_tag)
                    if record.type == 1:
                        work_tag.append(new_div_tag)
                    if record.type == 2:
                        education_tag.append(new_div_tag)
                    if record.type == 3:
                        other_tag.append(new_div_tag)

                if unsigned_records is not None:
                    for record in unsigned_records:
                        if record.endorsee == user.address:
                            new_div_tag = soup.new_tag("div")
                            new_div_tag["class"] = "callout"
                            role_tag = soup.new_tag("h5")
                            role_tag.string = record.role
                            new_div_tag.append(role_tag)
                            company_tag = soup.new_tag("h5")
                            company_tag.string = str(record.company)
                            new_div_tag.append(company_tag)
                            new_detail_tag = soup.new_tag("p")
                            new_detail_tag.string = record.detail
                            new_div_tag.append(new_detail_tag)
                            new_status_tag = soup.new_tag("p")
                            new_status_tag.string = "Pending"
                            new_div_tag.append(new_status_tag)
                            if record.type == 1:
                                work_tag.append(new_div_tag)
                            if record.type == 2:
                                education_tag.append(new_div_tag)
                            if record.type == 3:
                                other_tag.append(new_div_tag)

                dataset_tag = soup.find(id="organization-user")
                if organizations is not None:
                    for organization in organizations:
                        new_option_tag = soup.new_tag("option")
                        new_option_tag["value"] = organization.index
                        new_option_tag.string = organization.name
                        dataset_tag.append(new_option_tag)

                return str(soup)

        response = "What you are looking for is on Mars, and you are on Venus"
        return json.dumps(response)



    @app.route('/record', methods=['POST'])
    def create_record(self, request):
        session_id = request.getSession().uid.decode('utf-8')
        for instance in self.instances:
            if instance.session_id == session_id:
                user = instance.get_user_by_session(session_id)

                content = request.args
                role = content[b'role'][0].decode('utf-8')
                rtype = content[b'type'][0].decode('utf-8')
                detail = content[b'record-detail'][0].decode('utf-8')
                org = content[b'organization-id'][0].decode('utf-8')
                org = int(org)
                # Put this in a separate function - change this to get admin by organization
                organizations = self.get_all_organization()
                for organization in organizations:
                    if organization.index == org:
                        if len(organization.administrators) > 1:
                            endorser = organization.administrators[1]
                        else:
                            endorser = self.get_genesis_user_address()
                        record = Record(user.address, endorser, org, role, detail, int(rtype))
                        self.broadcast_record(record)
                        request.redirect('/dashboard')

        response = "What you are looking for is on Mars, and you are on Venus"
        return json.dumps(response)


    @app.route('/organization', methods=['GET'])
    def get_organization(self, request):

        session_id = request.getSession().uid.decode('utf-8')
        for instance in self.instances:
            if instance.session_id == session_id:
                user = instance.get_user_by_session(session_id)

                html_file = open('Frontend/organization.html').read()
                soup = BeautifulSoup(html_file, 'html.parser')

                organizations = self.get_organization_by_admin(user.address)
                organization_div = soup.find(id="user-organization")
                if organizations is not None:
                    for organization in organizations:
                        new_div_tag = soup.new_tag('div')
                        div_class = "cell large-12 medium-12 small-12"
                        new_div_tag["class"] = div_class
                        new_p_tag = soup.new_tag('p')
                        new_p_tag.string = organization.name
                        new_div_tag.append(new_p_tag)
                        new_form_tag = soup.new_tag('form', action="/admin/add", method="post", enctype="application/x-www-form-urlencoded")
                        new_input_tag = soup.new_tag("input", type="text")
                        new_input_tag['readonly'] = None
                        new_input_tag['name'] = "organization"
                        new_input_tag['value'] =  organization.index
                        new_form_tag.append(new_input_tag)
                        new_input_tag = soup.new_tag("input", type="text", placeholder="User Email")
                        new_input_tag['name'] = "user-email"
                        new_form_tag.append(new_input_tag)
                        new_button = soup.new_tag('button')
                        new_button["class"] = "button"
                        new_button.string = "Add Admin"
                        new_form_tag.append(new_button)
                        new_div_tag.append(new_form_tag)
                        organization_div.append(new_div_tag)
                return str(soup)

        response = "What you are looking for is on Mars, and you are on Venus"
        return json.dumps(response)



    @app.route('/organization', methods=['POST'])
    def create_organization(self, request):

        session_id = request.getSession().uid.decode('utf-8')
        for instance in self.instances:
            if instance.session_id == session_id:
                user = instance.get_user_by_session(session_id)

                content = request.args
                location = content[b'location'][0].decode('utf-8')
                admin = content[b'admin'][0].decode('utf-8')
                otype = content[b'otype'][0].decode('utf-8')
                name = content[b'oname'][0].decode('utf-8')
                website = content[b'website'][0].decode('utf-8')

                index = self.get_latest_organization_index()
                if index == 'None':
                    index = '1111111111111111'
                if int(admin) == 0:
                    address = self.get_genesis_user_address()
                    organization = Organization(int(index)+1, name, website, location, otype, [address])
                    self.broadcast_organization(organization)
                    request.redirect('/organization')
                else:
                    organization = Organization(int(index)+1, name, website, location, otype, [user.address])
                    self.broadcast_organization(organization)
                    request.redirect('/organization')

        response = "What you are looking for is on Mars, and you are on Venus"
        return json.dumps(response)

    @app.route('/record', methods=['GET'])
    def get_records(self, request):
        session_id = request.getSession().uid.decode('utf-8')
        for instance in self.instances:
            if instance.session_id == session_id:
                user = instance.get_user_by_session(session_id)

                html_file = open('Frontend/requests.html').read()
                soup = BeautifulSoup(html_file, 'html.parser')
                requests_div = soup.find(id='record-requests')
                unsigned_records = self.get_all_unconfirmed_records(user.address)

                if unsigned_records is not None:
                    for record in unsigned_records:
                        if record.endorser == user.address:
                            new_div_tag = soup.new_tag("div")
                            new_div_tag["class"] = "cell large-5 medium-5 small-12 large-offset-1 medium-offset-1"
                            callout_tag = soup.new_tag("div")
                            callout_tag["class"] = "callout"
                            new_form_tag = soup.new_tag('form', action="/sign", method="post", enctype="application/x-www-form-urlencoded")
                            new_form_tag['accept-charset']='utf-8'
                            new_input_tag = soup.new_tag("input", type="text")
                            new_input_tag['readonly'] = None
                            new_input_tag['name'] = "endorsee"
                            new_input_tag['value'] = record.endorsee
                            new_form_tag.append(new_input_tag)
                            new_input_tag = soup.new_tag("input", type="text")
                            new_input_tag['readonly'] = None
                            new_input_tag['name'] = "role"
                            new_input_tag['value'] = record.role
                            new_form_tag.append(new_input_tag)
                            new_input_tag = soup.new_tag("input", type="text")
                            new_input_tag['readonly'] = None
                            new_input_tag['name'] = "company"
                            new_input_tag['value'] = str(record.company)
                            new_form_tag.append(new_input_tag)
                            new_input_tag = soup.new_tag("input", type="text")
                            new_input_tag['readonly'] = None
                            new_input_tag['name'] = "detail"
                            new_input_tag['value'] = record.detail
                            new_form_tag.append(new_input_tag)
                            new_input_tag = soup.new_tag("input", type="text")
                            new_input_tag['readonly'] = None
                            new_input_tag['name'] = "type"
                            new_input_tag['value'] = str(record.type)
                            new_form_tag.append(new_input_tag)
                            new_input_tag = soup.new_tag("input", type="text")
                            new_input_tag['name'] = "private_key"
                            new_form_tag.append(new_input_tag)
                            new_button = soup.new_tag('button')
                            new_button["class"] = "button"
                            new_button.string = "Sign"
                            new_form_tag.append(new_button)
                            new_div_tag.append(new_form_tag)
                            requests_div.append(new_div_tag)

                return str(soup)

        response = "What you are looking for is on Mars, and you are on Venus"
        return json.dumps(response)

    @app.route('/sign', methods=['POST'])
    def sign_record(self, request):
        session_id = request.getSession().uid.decode('utf-8')
        for instance in self.instances:
            if instance.session_id == session_id:
                user = instance.get_user_by_session(session_id)
                endorser = user.address

                content = request.args
                endorsee = content[b'endorsee'][0].decode('utf-8')
                role = content[b'role'][0].decode('utf-8')
                rtype = content[b'type'][0].decode('utf-8')
                detail = content[b'detail'][0].decode('utf-8')
                org = content[b'company'][0].decode('utf-8')
                org = int(org)
                record = Record(endorsee, endorser, org, role, detail, int(rtype))
                private_key = content[b'private_key'][0].decode('utf-8')
                signature = record.sign(private_key)
                print (signature)
                self.broadcast_record(record)
                request.redirect('/record')

        response = "What you are looking for is on Mars, and you are on Venus"
        return json.dumps(response)

    @app.route('/wallet', methods=['GET'])
    def wallet(self, request):

        session_id = request.getSession().uid.decode('utf-8')
        for instance in self.instances:
            if instance.session_id == session_id:
                user = instance.get_user_by_session(session_id)
                endorser = user.address

                html_file = open('Frontend/wallet.html').read()
                soup = BeautifulSoup(html_file, 'html.parser')

                balance_tag = soup.find(id="balance")
                balance = self.get_balance(user.address)
                balance_tag.string = balance

                return str(soup)

        response = "What you are looking for is on Mars, and you are on Venus"
        return json.dumps(response)

    @app.route('/admin/add', methods=['POST'])
    def add_admin(self, request):
        session_id = request.getSession().uid.decode('utf-8')
        for instance in self.instances:
            if instance.session_id == session_id:
                user = instance.get_user_by_session(session_id)
                endorser = user.address

                content = request.args
                organization = content[b'organization'][0].decode('utf-8')
                email = content[b'user-email'][0].decode('utf-8')
                self.add_admin_by_email(organization, email)
                request.redirect('/organization')

        response = "What you are looking for is on Mars, and you are on Venus"
        return json.dumps(response)

    @app.route('/view/<index>', methods=['GET'], branch=True)
    def view_user(self, request, index):

        user = self.get_user_by_index(index)

        if user is not None:
            html_file = open('Frontend/view.html').read()
            soup = BeautifulSoup(html_file, 'html.parser')

            soup.find(id='name').string = user.name
            soup.find(id='email').string = user.email
            soup.find(id='headline').string = user.headline
            soup.find(id='summary').string = user.summary
            soup.find(id='location').string = user.location

            return str(soup)

        else:
            message = "User not Found"
            return json.dumps(message)

    @app.route('/logout', methods=['GET'])
    def logout(self, request):

        session_id = request.getSession().uid.decode('utf-8')
        for instance in self.instances:
            if instance.session_id == session_id:
                self.instances.remove(instance)
                request.getSession().expire()
                request.redirect('/')

        response = "What you are looking for is on Mars, and you are on Venus"
        return json.dumps(response)

    @app.route('/purchase', methods=['POST'])
    def buy_coins(self, request):

        message = "Currently not working"
        return json.dumps(message)


if __name__ == '__main__':

    Server()
