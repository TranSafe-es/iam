################################################
# Author: Bruno Silva - brunomiguelsilva@ua.pt #
################################################

import sys
import os
import urllib
import uuid
import logging
import requests
import datetime
import json
import base64
import httplib2
import flask

from flask_restful import reqparse, abort, Api, Resource
from flask import request, redirect, make_response, session, Response, Blueprint
from oauth2client import client

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from settings import *
from db import db_session
from models import Users

authorization = Blueprint('authorization', __name__)

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

        # Signup
        if user == None:
            headers = {}
            credentials.apply(headers)
            response = requests.get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json", headers=headers)

            data = response.json()

            user = Users(uid=google_id, email=data["email"], first_name=data["given_name"], last_name=data["family_name"], picture=data["picture"])

            db_session.add(user)
            db_session.commit()

        # Login
        if not valid_token(user):
            # Renew token
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
        return build_error_response("Missing authentication", \
                                    401,\
                                    "Access-Token header not present in the request")

    access_token = request.headers.get('Access-Token')

    user = Users.query.filter_by(access_token=access_token).first()
    if user == None:
        return build_error_response("Invalid authentication", \
                                    401,\
                                    "Access-Token is invalid for this service")

    user.token_valid = False

    db_session.commit()

    #return redirect(request.referrer, code=302)
    return build_response("", \
                        200,\
                        "User successfuly logged out")


@authorization.route("/validate", methods = ['POST'])
def validate():
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

    return build_response("", \
                        200,\
                        "Request provided is valid")


@authorization.route("/user", methods = ['GET'])
def get_user():
    if 'Access-Token' in flask.request.headers:
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

    elif 'email' in request.args:
        email = request.args.get('email')
        user = Users.query.filter_by(email=email).first()

        if user == None:
            return build_error_response("Invalid argument", \
                                    404,\
                                    "Email provided is invalid for this service")

    else:
        return build_error_response("Missing field", \
                                    400,\
                                    "Neither Address field or Access-Token Header present in the request")

    return build_response(user.serialize, \
                        200,\
                        "User information retrieved")


@authorization.route("/user/add_user_data", methods = ['POST'])
def add_user_data():
    if 'address' not in request.form:
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

    return build_response(user.serialize, \
                                    200,\
                                    "User information successfully updated")

def valid_token(user):
    if user.token_valid == False:
        return False

    expiringDate = user.creation_date + datetime.timedelta(seconds=TOKEN_DURATION)

    if datetime.datetime.now() > expiringDate:
        return False

    return True


def build_response(data, status, desc):
    jd = {"status_code:" : status, "error": "", "description": desc, "data": data}
    resp = Response(response=json.dumps(jd), status=status, mimetype="application/json")
    return resp

def build_error_response(error_title, status, error_desc):
    jd = {"status_code:" : status, "error": error_title, "description": error_desc, "data": ""}
    resp = Response(response=json.dumps(jd), status=status, mimetype="application/json")
    return resp

