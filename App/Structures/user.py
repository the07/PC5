import json

class User(object):

    def __init__(self, index, address, email, password, name, headline, summary, location, records=None):

        self._index = index
        self._address = address
        self._email = email
        self._password = password
        self._name = name
        self._headline = headline
        self._summary = summary
        self._location = location
        if records is None:
            self._records = []
        else:
            self._records = records

    @property
    def index(self):
        return self._index

    @property
    def address(self):
        return self._address

    @property
    def email(self):
        return self._email

    @property
    def password(self):
        return self._password

    @property
    def name(self):
        return self._name

    @property
    def headline(self):
        return self._headline

    @property
    def summary(self):
        return self._summary

    @property
    def location(self):
        return self._location

    @property
    def records(self):
        return self._records

    @classmethod
    def from_json(cls, user_json):
        user = cls(user_json['address'], user_json['email'], user_json['password'], user_json['name'], user_json['headline'], user_json['summary'], user_json['location'], user_json.get('records', None))
        return user

    def add_record(self, record):
        self._records.append(record)
        return

    def to_json(self):
        return json.dumps(self, default=lambda o: {key.lstrip('_'):value for key, value in o.__dict__.items()}, sort_keys=True)

    def __repr__(self):
        return "<User: Address - {}>".format(self._address)

    def __str__(self):
        return str(self.__dict__)

    def __eq__(self, other):
        return self._address == other._address

    def __ne__(self, other):
        return not self == other
