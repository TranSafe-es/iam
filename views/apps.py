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
from flask import request, render_template, redirect, Response, url_for, Blueprint, session, abort
from functools import wraps

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from settings import *
from db import db_session
from models import Apps

apps = Blueprint('apps', __name__)

import logging
logging.basicConfig(stream=sys.stderr)
logging.getLogger().setLevel(logging.DEBUG)
log = logging.getLogger()

@apps.route("/register", methods = ['GET'])
def register():
    return render_template('create_app.html')

@apps.route("/create", methods = ['POST'])
def create():
    if "admin_email" not in request.form:
        build_html_error_response("Missing Field", 400, "Missing admin email when registering app")
    if "name" not in request.form:
        build_html_error_response("Missing Field", 400, "Missing name when registering app")
    if "homepage" not in request.form:
        build_html_error_response("Missing Field", 400, "Missing homepage when registering app")
    if "callback_url" not in request.form:
        build_html_error_response("Missing Field", 400, "Missing callback when registering app")

    app = Apps(request.form.get("admin_email"), request.form.get("name"), request.form.get("homepage"), request.form.get("callback_url"))
    db_session.add(app)
    db_session.commit()

    return redirect(url_for("apps.get", client_id=app.client_id))

@apps.route("/edit", methods = ['GET'])
def edit_proxy():
    return render_template('edit_app_proxy.html')

@apps.route("/edit", methods = ['POST'])
def edit_data():
    if "admin_email" not in request.form:
        build_html_error_response("Missing Field", 400, "Missing admin email when registering app")
    if "name" not in request.form:
        build_html_error_response("Missing Field", 400, "Missing name when registering app")
    if "homepage" not in request.form:
        build_html_error_response("Missing Field", 400, "Missing homepage when registering app")
    if "callback_url" not in request.form:
        build_html_error_response("Missing Field", 400, "Missing callback when registering app")

    app = Apps.query.filter_by(client_id=session["client_id"]).first()
    app.name = request.form.get("name")
    app.admin_email = request.form.get("admin_email")
    app.homepage = request.form.get("homepage")
    app.callback = request.form.get("callback_url")

    db_session.commit()

    return redirect(url_for("apps.get", client_id=app.client_id))

@apps.route("/edit/<client_id>", methods = ['GET'])
def edit(client_id):
    app = Apps.query.filter_by(client_id=client_id).first()
    if not app:
        abort(404)
    session["client_id"] = client_id
    return render_template('edit_app.html', app=app)

@apps.route("/", methods = ['GET'])
def view_proxy():
    return render_template('view_app_proxy.html')

@apps.route("/<client_id>", methods = ['GET'])
def get(client_id):
    app = Apps.query.filter_by(client_id=client_id).first()
    if app == None:
        build_html_error_response("Invalid App", 400, "Client id doesnt exist")
    return render_template("show_app.html", app=app)

@apps.route("/renew/<client_id>", methods = ['GET'])
def renew(client_id):
    app = Apps.query.filter_by(client_id=client_id).first()
    app.client_secret = base64.b32encode(os.urandom(100))
    return redirect(url_for("apps.get", client_id=app.client_id))

##########################################################################################

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

def require_api_key(api_method):
    @wraps(api_method)

    def check_api_key(*args, **kwargs):
        apitoken = None
        if 'API-Token' in request.headers:
            apitoken = request.headers.get('API-Token')
        elif 'api_token' in request.args:
            apitoken = request.args.get('api_token')

        app = Apps.query.filter_by(client_secret=apitoken).first()
        if app:
            session["apitoken"] = apitoken
            return api_method(*args, **kwargs)
        else:
            abort(401)

    return check_api_key
