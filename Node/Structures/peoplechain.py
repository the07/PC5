import json

from Structures.record import Record
from Structures.user import User
from Structures.organization import Organization

class Peoplechain(object):

    users = []
    unconfirmed_records = []
    organizations = []

    def __init__(self, remote_chain_data=None):

        if remote_chain_data is None:
            self.users = []
            self.unconfirmed_records = []
            self.organizations = []
        else:
            for user in remote_chain_data['users']:
                new_user = User.from_json(json.loads(user))
                self.add_user(new_user)
            for unconfirmed_record in remote_chain_data['unconfirmed_records']:
                record = Record.from_json(json.loads(unconfirmed_record))
                self.add_unconfirmed_record(record)
            for organization in remote_chain_data['organizations']:
                organization = Organization.from_json(json.loads(organization))
                self.add_organization(organization)

    def add_user(self, user):
        if not user in self.users:
            self.users.append(user)
            return

    def add_unconfirmed_record(self, record):
        if not record in self.unconfirmed_records:
            self.unconfirmed_records.append(record)
            return

    def add_organization(self, organization):
        self.organization.append(organization)

    def record_signed(self, record):
        for unconfirmed_record in self.unconfirmed_records:
            # Record now has signature, so we cannot simply use 'record in'
            if unconfirmed_record.endorsee == record.endorsee and unconfirmed_record.endorser == record.endorser and unconfirmed_record.detail == record.detail and unconfirmed_record.type == record.type and unconfirmed_record.role == record.role:
                self.unconfirmed_records.remove(unconfirmed_record)
                self.add_record_to_user(record)
                return

    def add_record_to_user(self, record):
        for user in self.users:
            if user.address == record.endorsee:
                user.add_record(record)
                return

    def get_user_by_address(self, address):
        for user in self.users:
            if user.address == address:
                return user
        return None

    def get_user_by_index(self, index):
        for user in self.users:
            if user.index == int(index):
                return user
        return None

    def add_organization_admin(self, index, address):
        for organization in self.organizations:
            if organization.index == int(index):
                organization.add_admin(address)
                return organization

    def get_organization_by_admin(self, address):
        for organization in self.organizations:
            if address in organization.admin:
                return organization
        return None

    def get_organization_by_index(self, index):
        for organization in self.organizations:
            if organization.index == int(index):
                return organization
        return None

    def get_balance(self, address):
        balance = 100
        for user in self.users:
            for record in user.records:
                if record.endorsee == address:
                    if record.endorser == self.get_genesis_user_address():
                        balance += 1000
                    else:
                        balance += 50
                if record.endorser == address:
                    balance -= 50
        return balance

    def get_genesis_user_address(self):
        for user in self.users:
            if user.index == 1000000000000001:
                return user.address

    def get_unconfirmed_records(self, address):
        ucrecords = []
        for record in self.unconfirmed_records:
            if record.endorser == address:
                ucrecords.append(record.to_json())
            if record.endorsee == address:
                ucrecords.append(record.to_json())
        return ucrecords

    def get_latest_user_index(self):
        return self.users[-1].index

    def get_latest_organization_index(self):
        if len(self.organizations) > 0:
            return self.organizations[-1].index
        else:
            return None

if __name__ == '__main__':
    pass
