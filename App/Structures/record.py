import coincurve
import hashlib
import json

class Record(object):

    def __init__(self, endorsee, endorser, company, role, detail, rtype, signature=None):
        self._endorsee = endorsee
        self._endorser = endorser
        self._company = company
        self._role = role
        self._detail = detail
        self._type = rtype
        self._signature = signature
        self._hash = None
        if signature is not None:
            self._hash = self._calculate_hash()

    @property
    def endorsee(self):
        return self._endorsee

    @property
    def endorser(self):
        return self._endorser

    @property
    def role(self):
        return self._role

    @property
    def type(self):
        return self._type

    @property
    def detail(self):
        return self._detail

    @property
    def signature(self):
        return self._signature

    @property
    def company(self):
        return self._company

    @property
    def hash(self):
        return self._hash

    @classmethod
    def from_json(cls, record_json):
        record = cls(record_json['endorsee'], record_json['endorser'], record_json['company'], record_json['role'], record_json['detail'], record_json['type'], record_json.get('signature', None))
        return record

    def _calculate_hash(self):

        data = {
            "endorsee": self._endorsee,
            "endorser": self._endorser,
            "company": self._company,
            "role":self.role,
            "detail": self._detail,
            "type": self._type,
            "signature": self._signature
        }

        data_json = json.dumps(data, sort_keys=True)
        hash_object = hashlib.sha256(data_json.encode('utf-8'))
        return hash_object.hexdigest()

    def sign(self, private_key):
        signature = coincurve.PrivateKey.from_hex(private_key).sign(self.to_signable()).hex()
        self._signature = signature
        self._hash = self._calculate_hash()
        return signature

    def to_signable(self):
        return ":".join((
            self._endorsee,
            self._endorser,
            str(self._company) #TODO: ADD MORE DATA
        )).encode('utf-8')

    def verify(self):
        points = list(map(int, self._endorser.split(":")))
        return coincurve.PublicKey.from_point(points[0], points[1]).verify(bytes.fromhex(self._signature), self.to_signable())

    def to_json(self):
        return json.dumps(self, default=lambda o: {key.lstrip('_'):value for key, value in o.__dict__.items()}, sort_keys=True)

    def __repr__(self):
        return "<Record for {}>".format(self._endorsee)

    def __str__(self):
        return str(self.__dict__)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other

if __name__ == '__main__':
    pass
