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
        request.redirect('/dashboard')

    @app.route('/dashboard', methods=['GET'])
    def user_dashboard(self, request):
        #From session get user
        #soup dashboard.html, give values, return soup
        pass

    @app.route('/record', methods=['POST'])
    def create_record(self, request):
        pass

    @app.route('/organization', methods=['GET'])
    def get_organization(self, request):
        pass

    @app.route('/organization', methods=['POST'])
    def create_organization(self, request):
        pass

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
        #Expire session data
        request.redirect('/')

    @app.route('/purchase', methods=['POST'])
    def buy_coins(self, request):
        pass

if __name__ == '__main__':

    Server()
