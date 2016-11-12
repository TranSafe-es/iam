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
from models import Users, Apps
from views.apps import require_api_key
from views.apps import apps

authorization = Blueprint('authorization', __name__)

import logging
logging.basicConfig(stream=sys.stderr)
logging.getLogger().setLevel(logging.DEBUG)
log = logging.getLogger()

@authorization.route("/", methods = ['GET'])
def home():
    message = ""
    return render_template('home.html', message=message)

@authorization.route("/login", methods = ['GET'])
@require_api_key
def login_html():
    app = Apps.query.filter_by(client_secret=session["apitoken"]).first()
    if not request.url_root.startswith(app.homepage):
        return build_html_error_response("Request origin missmatch", 400, "Request came from different origin that what was speficied in app.")
    if 'referer' in request.args:
        session['referrer'] = request.args.get('referer')
    else:
        session['referrer'] = request.referrer
    if session['referrer'] == None:
        session['referrer'] = app.callback
    if session['referrer'] != app.callback:
        return build_html_error_response("Callback url missmatch", 400, "Callback provided is diferent from the registered one")
    return render_template('login.html', name=app.name)

@authorization.route("/login", methods = ['POST'])
def login():
    if 'platform' not in request.form:
        return build_html_error_response("Missing parameter", \
                            400,\
                            "Missing platform parameter for authentication")
    platform = request.form['platform']
    session['platform'] = platform
    url = service_authorize(platform)
    if url == None:
        return build_html_error_response("Unsupported platform", \
                                    400, \
                                    "The specified platform is not available")
    response = redirect(url, code=302)
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@authorization.route("/login_callback", methods = ['GET'])
def login_callback():
    info = json.loads(session["info"])

    user = Users.query.filter_by(uid=info["id"]).first()

    # Signup
    if user == None:
        user = Users.query.filter_by(email=info["email"]).first()
        if user != None:
            if user.has_merged:
                user.access_token = base64.b64encode(os.urandom(16))
                user.creation_date = datetime.datetime.now()
                user.token_valid = True
                db_session.commit()
                return redirect(session['referrer']+ "?" +urllib.urlencode({"access_token": user.access_token}), 302)

            if session["platform"] == "facebook":
                return render_template("merge_option.html", facebook=info, google=user)
            elif session["platform"] == "google":
                return render_template("merge_option.html", facebook=user, google=info)

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

    return redirect(session['referrer']+ "?" +urllib.urlencode({"access_token": user.access_token}), 302)

@authorization.route("/merge", methods = ['POST'])
def merge():
    info = json.loads(session["info"])
    user = Users.query.filter_by(email=info["email"]).first()
    if request.form.get("choice") == session["platform"]:
        user.uid=info["uid"]
        user.email=info["email"]
        user.name=info["name"]
        user.picture=info["picture"]
        user.platform = info["platform"]

    user.access_token = base64.b64encode(os.urandom(16))
    user.creation_date = datetime.datetime.now()
    user.token_valid = True

    user.has_merged = True
    db_session.commit()

    return redirect(session['referrer']+ "?" +urllib.urlencode({"access_token": user.access_token}), 302)

@authorization.route("/validate", methods = ['POST'])
@require_api_key
def validate():
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
    user.creation_date = datetime.datetime.now()
    db_session.commit()
    return build_response("", \
                        200,\
                        "Request provided is valid")

@authorization.route("/logout", methods = ['GET'])
@require_api_key
def logout():
    if 'redirect_url' in request.args:
        referrer = request.args.get('redirect_url')
    else:
        referrer = request.referrer
    if 'Access-Token' not in request.headers and 'access_token' not in request.args:
        return build_html_error_response("Missing authentication", \
                                    400,\
                                    "Access-Token header not present in the request")
    if 'Access-Token' not in request.headers:
        access_token = request.args.get('access_token')
    else:
        access_token = request.headers.get('Access-Token')
    user = Users.query.filter_by(access_token=access_token).first()
    if user == None:
        return build_html_error_response("Invalid authentication", \
                                    401,\
                                    "Access-Token is invalid for this service")
    user.token_valid = False
    db_session.commit()

    return render_template("logout.html", referrer=referrer.split('?')[0], email=user.email)

################################################################################
@authorization.route("/user", methods = ['GET'])
@require_api_key
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
        uid = request.args.get('id')
        user = Users.query.filter_by(uid=uid).first()
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
@require_api_key
def add_user_data():
    phone = request.form.get('phone')
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
    if address:
        user.address = address
    if phone:
        user.phone = phone
    db_session.commit()
    return build_response(user.serialize, \
                                    200,\
                                    "User information successfully updated")

@authorization.route("/user/count", methods = ['GET'])
@require_api_key
def get_user_count():
    count = Users.query.count()
    return build_response(count, 200, "User count successfully retrieved")

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

def build_html_error_response(error_title, status, error_desc):
    jd = {"status_code:" : status, "error": error_title, "description": error_desc, "data": ""}
    resp = render_template("error.html", code=status, error_title=error_title, error_message=error_desc)
    return resp
################################################
