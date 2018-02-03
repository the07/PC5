import json

class Organization(object):

    admin = []
    def __init__(self, index, name, website, location, otype, admin=None):

        self._index = index
        self._name = name
        self._website = website
        self._location = location
        self._type = otype
        if admin is not None:
            self.add_admin(admin)
        else:
            self.admin = []

    @property
    def index(self):
        return self._index

    @property
    def name(self):
        return self._name

    @property
    def website(self):
        return self._website

    @property
    def location(self):
        return self._location

    @property
    def type(self):
        return self._type

    @property
    def admin(self):
        return self.admin

    @classmethod
    def from_json(cls, org_json):
        organization = cls(org_json['index'], org_json['name'], org_json['website'], org_json['location'], org_json['type'], org_json.get('admin', None))
        return organization

    def add_admin(self, address):
        self.admin.append(address)
        return

    def remove_admin(self, address):
        for admin in self.admin:
            if admin == address:
                self.admin.remove(address)
                return True
        return False

    def to_json(self):
        return json.dumps(self, default=lambda o: {key.lstrip('_'):value for key, value in o.__dict__.items()}, sort_keys=True)

    def __repr__(self):
        return "<User: Address - {}>".format(self._name)

    def __str__(self):
        return str(self.__dict__)

if __name__ == '__main__':
    pass
