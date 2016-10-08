
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
from flask import request, render_template, redirect, make_response, session
from flask import jsonify
from flask import Blueprint

import httplib2
from oauth2client import client


sys.path.insert(1, os.path.join(sys.path[0], '..'))

from settings import *
from db import db_session

from models import Users

from oauth2client import client


authorization = Blueprint('authorization', __name__)

@authorization.route("/", methods = ['GET'])
def index():
    return render_template('index.html')


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
        if not valid_token(user):
            #renew token
            user.access_token = base64.b64encode(os.urandom(16))
            user.creation_date = datetime.datetime.now()
            user.token_valid = True
            db_session.commit()

        response = redirect(session['referrer'], 302)
        response.headers['Access-Token'] = user.access_token
        return response


@authorization.route('/google/callback', methods = ['GET'])
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


@authorization.route("/logout", methods = ['GET'])
def logout():
    if 'Access-Token' not in flask.request.headers:
        return "ERROR - Access Token Header Required", 400

    access_token = request.headers.get('Access-Token')

    user = Users.query.filter_by(access_token=access_token).first()
    if user == None:
        return make_response("Invalid token", 400)

    user.token_valid = False

    db_session.commit()

    #return redirect(request.referrer, code=302)

    return make_response("User successfully logged out", 200)


@authorization.route("/validate", methods = ['POST'])
def validate():
    if 'Access-Token' not in flask.request.headers:
        return "ERROR - Access Token Header Required", 400

    access_token = request.headers.get('Access-Token')

    user = Users.query.filter_by(access_token=access_token).first()

    if user == None:
        return make_response("Invalid token", 400)

    if valid_token(user):
        return "Valid Request", 200

    return "User not logged in", 401


@authorization.route("/user", methods = ['GET'])
def get_user():
    if 'Access-Token' in flask.request.headers:
        access_token = request.headers.get('Access-Token')
        user = Users.query.filter_by(access_token=access_token).first()

        if user == None:
            return make_response("Invalid token", 400)

        if not valid_token(user):
            return "User unauthorized", 401

    elif 'email' in request.args:
        email = request.args.get('email')
        user = Users.query.filter_by(email=email).first()

        if user == None:
            return make_response("Invalid email", 400)

    else:
        return "ERROR - Access Token or email not provided", 400

    return make_response(str(user.serialize), 200)


@authorization.route("/user/add_user_data", methods = ['POST'])
def add_user_data():
    if 'address' not in flask.form:
        return build_error_response("Missing field", \
                                    400,\
                                    "Address field not present in the request")

    address = request.form.get('address')

    if 'Access-Token' not in flask.request.headers:
        return build_error_response("Missing authentication", \
                                    401,\
                                    "Access-Token header not present in the request")

    access_token = request.headers.get('Access-Token')

    user = Users.query.filter_by(access_token=access_token).first()

    if user == None:
        return build_error_response("Invalid authentication", \
                                    401,\
                                    "Access-Token is invalid for this service")

    if not valid_token(user):
        return build_error_response("Invalid authentication", \
                                    401,\
                                    "Access-Token is no longer valid, user logged out or token expired")

    user.address = address
    db_session.commit()

def valid_token(user):
    if user.token_valid == False:
        return False

    expiringDate = user.creation_date + datetime.timedelta(seconds=TOKEN_DURATION)

    if datetime.datetime.now() > expiringDate:
        return False

    return True


def build_response(data, status):
    jd = {"status_code:" : status, "error": error, "description": data}
    resp = Response(response=jd, status=status, mimetype="application/json")
    return resp

def build_error_response(error_title, status, error_desc):
    jd = {"status_code:" : status, "error": error, "description": data}
    resp = Response(response=jd, status=status, mimetype="application/json")
    return resp





