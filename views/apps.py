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
