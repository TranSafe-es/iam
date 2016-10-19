
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
    picture_url = Column(String)
    platform = Column(String)

    # Extra user fields (can be added over time)
    address = Column(String)

    # Authentication required fields
    access_token = Column(String, unique=True)
    creation_date = Column(DateTime, nullable=False, default=datetime.datetime.now())
    token_valid = Column(Boolean, default=True)

    def __init__(self, uid, email, name, picture, platform, address=""):
        self.uid = uid
        self.email = email
        self.name = name
        self.picture_url = picture
        self.platform = platform

        self.address = address

        self.creation_date = datetime.datetime.now()
        self.access_token = base64.b64encode(os.urandom(16))
        self.token_valid = True

    def __repr__(self):
        return "<User(uid='%s', Name='%s', Email='%s', Picture='%s', Platform='%s')>" % (self.uid, self.name, self.email, self.picture_url, self.platform)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'uid': self.uid,
            'name': self.name,
            'email': self.email,
            'picture_url': self.picture_url,
            'platform': self.platform,

            'address': self.address

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
