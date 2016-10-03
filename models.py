
import datetime
import uuid
import os
import base64
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from db import Base


class Users(Base):
    __tablename__ = 'users'

    uid = Column(String, primary_key=True)
    email = Column(String, unique=True)
    first_name = Column(String)
    last_name = Column(String)
    picture_url = Column(String)

    access_token = Column(String, unique=True)
    creation_date = Column(DateTime, nullable=False, default=datetime.datetime.now())
    token_valid = Column(Boolean, default=True)

    def __init__(self, uid, email, first_name, last_name, picture):
        self.uid = uid
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.picture_url = picture

        self.creation_date = datetime.datetime.now()
        self.access_token = base64.b64encode(os.urandom(16))
        self.token_valid = True

    def __repr__(self):
        return "<User(uid='%s', Name='%s', Email='%s', Picture='%s')>" % (self.uid, (self.first_name + " " + self.last_name) , self.email, self.picture_url)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'uid': self.uid,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'picture_url': self.picture_url,

            "access_token": self.access_token,
            "creation_date": self.creation_date,
            "token_valid": self.token_valid
        }
