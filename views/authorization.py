################################################
# Author: Bruno Silva - brunomiguelsilva@ua.pt #
################################################

import sys
import os
import datetime
import json
import base64
from rauth import *
from flask_restful import Api, Resource
from flask import request, render_template, redirect, Response, url_for, Blueprint, session

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from settings import *
from db import db_session
from models import Users

authorization = Blueprint('authorization', __name__)

@authorization.route("/login", methods = ['GET'])
def login_html():
    if request.referrer != None:
        session['referrer'] = request.referrer
    if 'access_token' in request.args:
        session['Access-Token'] = request.args.get('access_token')
    return render_template('login.html')

@authorization.route("/login", methods = ['POST'])
def login():
    if 'platform' not in request.form:
        return build_error_response("Missing parameter", \
                            400,\
                            "Missing platform parameter for SONATA authentication")
    platform = request.form['platform']
    session['platform'] = platform
    url = service_authorize(platform)
    if url == None:
        return build_error_response("Unsupported platform", \
                                    400, \
                                    "The specified platform is not available")
    if 'Access-Token' not in session:
        response = redirect(url, code=302)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    else:
        access_token = session['Access-Token']
        user = Users.query.filter_by(access_token = access_token).first()
        if user == None:
            return build_error_response("Invalid authentication", \
                                        401,\
                                        "Access-Token is invalid for this service")
        if not valid_token(user):
            response = redirect(url, code=302)
            response.headers['Access-Control-Allow-Origin'] = '*'
            return response

        response = redirect(session["referrer"], code=302)
        response.headers['Access-Token'] = user.access_token
        return response

@authorization.route("/login_callback", methods = ['GET'])
def login_callback():
    info = json.loads(session["info"])
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

    response = redirect(session['referrer'], 302)
    response.headers['Access-Token'] = user.access_token
    return response

@authorization.route("/validate", methods = ['POST'])
def validate():
    if 'Access-Token' not in request.headers:
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

    if request.referrer != None:
        return redirect(request.referrer, code=302)
    else:
        return build_response("", \
                            200,\
                            "User successfuly logged out")

def service_authorize(platform):
    if platform == "facebook":
        service = OAuth2Service(
                   name=platform,
                   client_id=FACEBOOK_CLIENT_ID,
                   client_secret=FACEBOOK_CLIENT_SECRET,
                   authorize_url=FACEBOOK_AUTH_URL,
                   access_token_url=FACEBOOK_TOKEN_URL)
        params = {'scope': 'email public_profile',
                  'redirect_uri': url_for("facebook.callback", _external=True),
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
                  'redirect_uri': url_for("google.callback", _external=True),
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
