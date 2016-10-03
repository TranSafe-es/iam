
import sys
import os
import urllib
import uuid
import logging
import requests
import datetime
import json
import base64
from flask_restful import reqparse, abort, Api, Resource
from flask import request, render_template, redirect, make_response
from flask import jsonify
from flask import Blueprint

import httplib2
from oauth2client import client


sys.path.insert(1, os.path.join(sys.path[0], '..'))

from settings import *
from db import db_session
from db import redis_db

from models import Users

from oauth2client import client


authorization = Blueprint('authorization', __name__)

@authorization.route("/", methods = ['GET'])
def index():
    return render_template('index.html')

@authorization.route("/signup", methods = ['GET'])
def signup():

    flow = client.flow_from_clientsecrets(
        'client_secrets.json',
        scope=['profile', 'email'],
        redirect_uri='http://localhost:5001/google/callback')

    auth_uri = flow.step1_get_authorize_url()

    response = redirect(auth_uri)

    return response

@authorization.route("/login", methods = ['GET'])
def login():
    # log in
    return make_response("User loged in", 200)
