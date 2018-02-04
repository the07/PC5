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
                response_content = response.json()
                if response_content is not '':
                    user_json = json.loads(response_content['user'])
                    return User.from_json(user_json)
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
                print (response_content)
                return
            except requests.exceptions.RequestException as re:
                pass

    def get_organization_by_admin(self, address):
        self.request_nodes_from_all()
        for node in self.full_nodes:
            url = self.ORGANIZATION_GET_URL.format(node, self.FULL_NODE_PORT, address)
            organizations = []
            try:
                response = requests.get(url)
                if int(response.content.decode('utf-8')) == 0:
                    return None
                else:
                    response_content = json.loads(response.content.decode('utf-8'))
                    for organization in response_content['organizations']:
                        organization = Organization.from_json(json.loads(organization))
                        organizations.append(organization)
                    return organizations
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
            'redirect_uri': 'http://localhost:30906/linkedin',
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
        password_hash = sha256(password).hexdigest()
        user = self.get_user_by_email(email)
        #Handle user does not exist
        if user.password == password_hash:
            session_id = request.getSession().uid.decode('utf-8')
            instance = Instance(session_id, user)
            self.instances.append(instance)
            request.redirect('/dashboard')
        else:
            html_file = open('Frontend/index.html').read()
            soup = BeautifulSoup(html_file, 'html.parser')

            soup.find(id='message').string = "Incorrect email or password"
            return str(soup)

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

                source="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=" + user.address
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

                for record in user.records:
                    new_div_tag = soup.new_tag("div")
                    new_div_tag["class"] = "callout"
                    role_tag = soup.new_tag("h5")
                    role_tag.string = record.role
                    new_div_tag.append(role_tag)
                    company_tag = soup.new_tag("h5")
                    company_tag.string = record.company
                    new_div_tag.append(company_tag)
                    new_detail_tag = soup.new_tag("p")
                    new_detail_tag.string = record.detail
                    new_div_tag.append(new_detail_tag)
                    new_status_tag = soup.new_tag("p")
                    if record.signature is None:
                        new_status_tag.string = 'Pending'
                    else:
                        new_status_tag.string = record.signature
                    new_div_tag.append(new_status_tag)
                    if record.type == 1:
                        work_tag.append(new_div_tag)
                    if record.type == 2:
                        education_tag.append(new_div_tag)
                    if record.type == 3:
                        other_tag.append(new_div_tag)

                organizations = self.get_all_organization()
                #users = self.get_all_users()

                dataset_tag = soup.find(id="organization-user")
                if organizations is not None:
                    for organization in organizations:
                        new_option_tag = soup.new_tag("option")
                        new_option_tag["value"] = organization.index
                        new_option_tag.string = organization.name
                        dataset_tag.append(new_option_tag)

                return str(soup)
            else:
                response = "What you are looking for is on Mars, and you are on Venus"
                return json.dumps(response)

    @app.route('/record', methods=['POST'])
    def create_record(self, request):
        content = request.args
        print (content)

    @app.route('/organization', methods=['GET'])
    def get_organization(self, request):

        session_id = request.getSession().uid.decode('utf-8')
        for instance in self.instances:
            if instance.session_id == session_id:
                user = instance.get_user_by_session(session_id)

                html_file = open('Frontend/organization.html').read()
                soup = BeautifulSoup(html_file, 'html.parser')

                organizations = self.get_organization_by_admin(user.address)
                if organizations is not None:
                    organization_div = soup.find(id='user-organization')
                    for organization in organizations:
                        new_div = soup.new_tag('div')
                        new_div['class'] = "cell large-6 medium-6 small-12"
                        new_a_tag = soup.new_tag['a']
                        new_a_tag['href'] = '/view/organization/' + organization.index
                        new_div.append(new_a_tag)
                        organization_div.append(new_div)
                return str(soup)
            else:
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
                if index is None:
                    index = '1111111111111111'
                if int(admin) == 0:
                    organization = Organization(int(index)+1, name, website, location, otype)
                    self.broadcast_organization(organization)
                    request.redirect('/organization')
                else:
                    organization = Organization(int(index)+1, name, website, location, otype, user.address)
                    self.broadcast_organization(organization)
                    request.redirect('/organization')
            else:
                response = "What you are looking for is on Mars, and you are on Venus"
                return json.dumps(response)

    @app.route('/record', methods=['GET'])
    def get_records(self, request):
        pass

    @app.route('/sign', methods=['POST'])
    def sign_record(self, request):
        pass

    @app.route('/wallet', methods=['GET'])
    def wallet(self, request):
        pass

    @app.route('/logout', methods=['GET'])
    def logout(self, request):

        session_id = request.getSession().uid.decode('utf-8')
        for instance in self.instances:
            if instance.session_id == session_id:
                self.instances.remove(instance)
                request.getSession().expire()
                request.redirect('/')
            else:
                response = "What you are looking for is on Mars, and you are on Venus"
                return json.dumps(response)

    @app.route('/purchase', methods=['POST'])
    def buy_coins(self, request):
        pass

if __name__ == '__main__':

    Server()
