################################################
# Author: Bruno Silva - brunomiguelsilva@ua.pt #
################################################

import sys
import os
import datetime
import json
import base64
import urllib
from rauth import *
from flask_restful import Api, Resource
from flask import request, render_template, redirect, Response, url_for, Blueprint, session

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from settings import *
from db import db_session
from models import Users

authorization = Blueprint('authorization', __name__)

import logging
logging.basicConfig(stream=sys.stderr)
logging.getLogger().setLevel(logging.DEBUG)
log = logging.getLogger()

@authorization.route("/login", methods = ['GET'])
def login_html():
    if 'referer' in request.args:
        session['referrer'] = request.args.get('referer')
    else:
        session['referrer'] = request.referrer
    return render_template('login.html')

@authorization.route("/login", methods = ['POST'])
def login():
    if 'platform' not in request.form:
        return build_error_response("Missing parameter", \
                            400,\
                            "Missing platform parameter for authentication")
    platform = request.form['platform']
    session['platform'] = platform
    url = service_authorize(platform)
    if url == None:
        return build_error_response("Unsupported platform", \
                                    400, \
                                    "The specified platform is not available")
    response = redirect(url, code=302)
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@authorization.route("/login_callback", methods = ['GET'])
def login_callback():
    info = json.loads(session["info"])

    user = Users.query.filter_by(email=info["email"]).first()
    if user != None:
        return build_error_response("Duplicate account", \
                                    400,\
                                    "An account with that email already exists, maybe already signup with diferent service using the same email")
                                    
    user = Users.query.filter_by(uid=info["id"]).first()

    # Signup
    if user == None:
        user = Users(uid=info["id"], email=info["email"], name=info["name"], picture=info["picture"], platform=info["platform"])
        db_session.add(user)
        db_session.commit()

    # Login
    if not valid_token(user):
        # Renew token
        user.access_token = base64.b64encode(os.urandom(16))
        user.creation_date = datetime.datetime.now()
        user.token_valid = True
        db_session.commit()

    response = redirect(session['referrer']+ "?" +urllib.urlencode({"access_token": user.access_token}), 302)
    return response

@authorization.route("/validate", methods = ['POST'])
def validate():
    if 'Access-Token' not in request.headers:
        return build_error_response("Missing authentication", \
                                    400,\
                                    "Access-Token header not present in the request")
    access_token = request.headers.get('Access-Token')
    log.debug(access_token)
    user = Users.query.filter_by(access_token=access_token).first()
    log.debug(user)
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

@authorization.route("/logout", methods = ['GET'])
def logout():
    if 'redirect_url' in request.args:
        referrer = request.args.get('redirect_url')
    else:
        referrer = request.referrer
    if 'Access-Token' not in request.headers and 'access_token' not in request.args:
        return build_error_response("Missing authentication", \
                                    400,\
                                    "Access-Token header not present in the request")
    if 'Access-Token' not in request.headers:
        access_token = request.args.get('access_token')
    else:
        access_token = request.headers.get('Access-Token')
    user = Users.query.filter_by(access_token=access_token).first()
    if user == None:
        return build_error_response("Invalid authentication", \
                                    401,\
                                    "Access-Token is invalid for this service")
    user.token_valid = False
    db_session.commit()

    return render_template("logout.html", referrer=referrer.split('?')[0], email=user.email)

################################################################################
@authorization.route("/user", methods = ['GET'])
def get_user():
    if 'Access-Token' in request.headers:
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
        return build_response(user.serialize, \
                            200,\
                            "User information retrieved")

    elif 'email' in request.args:
        email = request.args.get('email')
        user = Users.query.filter_by(email=email).first()
        if user == None:
            return build_error_response("Invalid argument", \
                                    404,\
                                    "Email provided is invalid for this service")

        else:
            return build_response(user.simple_serialize, \
                            200,\
                            "User information retrieved")

    elif 'id' in request.args:
        id = request.args.get('id')
        user = Users.query.filter_by(id=id).first()
        if user == None:
            return build_error_response("Invalid argument", \
                                    404,\
                                    "ID provided is invalid for this service")
        else:
            return build_response(user.serialize, \
                            200,\
                            "User information retrieved")
    else:
        return build_error_response("Missing field", \
                                    400,\
                                    "Neither email or Access-Token Header present in the request")

@authorization.route("/user/add_user_data", methods = ['POST'])
def add_user_data():
    if 'address' not in request.form:
        return build_error_response("Missing field", \
                                    400,\
                                    "Address field not present in the request")
    address = request.form.get('address')
    if 'Access-Token' not in request.headers:
        return build_error_response("Missing authentication", \
                                    400,\
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

############################################################################################

def service_authorize(platform):
    if platform == "facebook":
        service = OAuth2Service(
                   name=platform,
                   client_id=FACEBOOK_CLIENT_ID,
                   client_secret=FACEBOOK_CLIENT_SECRET,
                   authorize_url=FACEBOOK_AUTH_URL,
                   access_token_url=FACEBOOK_TOKEN_URL)
        params = {'scope': 'email public_profile',
                  'redirect_uri': FACEBOOK_CALLBACK,
                  'response_type': 'code'}
        url = service.get_authorize_url(**params)
        return url
    elif platform == "google":
        service = OAuth2Service(
                   name=platform,
                   client_id=GOOGLE_CLIENT_ID,
                   client_secret=GOOGLE_CLIENT_SECRET,
                   authorize_url=GOOGLE_AUTH_URL,
                   access_token_url=GOOGLE_TOKEN_URL)
        params = {'scope': "profile email https://www.googleapis.com/auth/userinfo.profile",
                  'redirect_uri': GOOGLE_CALLBACK,
                  'response_type': 'code'}
        url = service.get_authorize_url(**params)
        return url
    else:
        return None

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
################################################
