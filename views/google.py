
import sys
import os
import requests
import logging
import json
from datetime import datetime, timedelta
from flask_restful import reqparse, abort, Api, Resource
from flask import request
from flask import jsonify, make_response, redirect
from flask import Blueprint

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from settings import *
from db import db_session
from models import Users

from db import redis_db

from oauth2client import client

google = Blueprint('google', __name__)

@google.route("/callback", methods = ['GET'])
def auth_callback():
    error = request.args.get("error")
    if error != None:
        print error
        return redirect("/signup_callback", code=400)

    code = request.args.get("code")

    flow = client.flow_from_clientsecrets(
        'client_secrets.json',
        scope=['profile', 'email', "https://www.googleapis.com/auth/userinfo.profile"],
        redirect_uri='http://localhost:5001/google/callback')

    credentials = flow.step2_exchange(code)

    print credentials.json()

    #email = credentials.id_token['email']
    google_id = credentials.id_token['sub']

    user = Users.query.filter_by(uid=google_id).first()

    if user == None:
        #signup
        headers = {}
        credentials.apply(headers)
        response = requests.get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json", headers=headers)

        data = response.json()

        user = User(uid=google_id, email=data["email"], first_name=data["given_name"], last_name=data["family_name"], picture=data["picture"])

        db_session.add(user)
        db_session.commit()

    state = str(uuid.uuid4())

    session_redis = {"operation": "login"}

    redis_db.set(state, json.dumps(session_redis))

    return redirect("/login_callback" + "?state=" + state, code=302)



