
import datetime
import uuid
import os
import base64
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from db import Base


class Users(Base):
    __tablename__ = 'users'

    # Oauth fields
    uid = Column(String, primary_key=True)
    email = Column(String, unique=True)
    name = Column(String)
    picture = Column(String)
    platform = Column(String)

    # Extra user fields (can be added over time)
    address = Column(String)
    phone = Column(String)

    # Authentication required fields
    access_token = Column(String, unique=True)
    creation_date = Column(DateTime, nullable=False, default=datetime.datetime.now())
    token_valid = Column(Boolean, default=True)

    # Extra application fields
    has_merged = Column(Boolean, default=False)


    def __init__(self, uid, email, name, picture, platform, address="", phone=""):
        self.uid = uid
        self.email = email
        self.name = name
        self.picture = picture
        self.platform = platform

        self.address = address
        self.phone = phone

        self.creation_date = datetime.datetime.now()
        self.access_token = base64.b64encode(os.urandom(16))
        self.token_valid = True

    def __repr__(self):
        return "<User(uid='%s', Name='%s', Email='%s', Picture='%s', Platform='%s')>" % (self.uid, self.name, self.email, self.picture, self.platform)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'uid': self.uid,
            'name': self.name,
            'email': self.email,
            'picture_url': self.picture,
            'platform': self.platform,

            'address': self.address,
            'phone': self.phone,

            # Doesn't make sense for user to get this information
            "access_token": self.access_token,
            # "creation_date": self.creation_date.strftime('%d-%m-%Y %H:%M'),
            # "token_valid": self.token_valid
        }
    @property
    def simple_serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'uid': self.uid
        }

class Apps(Base):
    __tablename__ = 'apps'

    client_id = Column(String, primary_key=True, default=str(uuid.uuid4()))
    client_secret = Column(String, unique=True, default=base64.b32encode(os.urandom(100)))
    valid = Column(Boolean, default=True)

    name = Column(String, nullable=False)
    admin_email = Column(String, nullable=False)
    homepage = Column(String, nullable=False)
    callback = Column(String, nullable=False)

    def __init__(self, admin_email, name, homepage, callback):
        self.admin_email = admin_email
        self.name = name
        self.homepage = homepage
        self.callback = callback

        self.client_id = str(uuid.uuid4())
        self.client_secret = base64.b32encode(os.urandom(100))
        self.valid = True
