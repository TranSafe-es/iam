
import sys
import os
import urllib
import uuid
import logging
import requests
import datetime
import json
import base64
import flask
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


# @authorization.route("/login", methods = ['GET'])
# @authorization.route("/signup", methods = ['GET'])
# def signup():
#     flow = client.flow_from_clientsecrets(
#         'client_secrets.json',
#         scope=['profile', 'email', "https://www.googleapis.com/auth/userinfo.profile"],
#         redirect_uri='http://localhost:5001/google/callback')

#     auth_uri = flow.step1_get_authorize_url()

#     response = redirect(auth_uri)

#     return response


# @authorization.route("/login_callback", methods = ['GET'])
# def login():

#     return



@authorization.route("/login", methods = ['GET'])
@authorization.route("/signup", methods = ['GET'])
def login():
    if request.referrer != None:
        flask.session['referrer'] = request.referrer
    if 'credentials' not in flask.session:
        return flask.redirect(flask.url_for('authorization.oauth2callback'))
    credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
    if credentials.access_token_expired:
        return flask.redirect(flask.url_for('authorization.oauth2callback'))
    else:
        # login/signup
        google_id = credentials.id_token['sub']

        user = Users.query.filter_by(uid=google_id).first()

        if user == None:
            #signup
            headers = {}
            credentials.apply(headers)
            response = requests.get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json", headers=headers)

            data = response.json()

            user = Users(uid=google_id, email=data["email"], first_name=data["given_name"], last_name=data["family_name"], picture=data["picture"])

            db_session.add(user)
            db_session.commit()

        #login
        return flask.redirect(flask.session['referrer'])


@authorization.route('/google/callback')
def oauth2callback():
    flow = client.flow_from_clientsecrets(
      'client_secrets.json',
      scope=['profile', 'email', "https://www.googleapis.com/auth/userinfo.profile"],
      redirect_uri="http://localhost:5001/google/callback")
    if 'code' not in flask.request.args:
        auth_uri = flow.step1_get_authorize_url()
        return flask.redirect(auth_uri)
    else:
        auth_code = flask.request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        flask.session['credentials'] = credentials.to_json()
        return flask.redirect(flask.url_for('authorization.login'))
