################################################
# Author: Bruno Silva - brunomiguelsilva@ua.pt #
################################################

import sys
import os
import json
from rauth import *
from flask_restful import Api, Resource
from flask import redirect, session, Blueprint, request, url_for, Response

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from settings import *

google = Blueprint('google', __name__)

@google.route("/callback", methods = ['GET'])
def callback():
    if 'code' not in request.args:
        return build_error_response("Invalid Request", \
                                    400,\
                                    "User refused the platform authorization")
    platform = session['platform']
    code = request.args.get('code')
    service = OAuth2Service(
               name=platform,
               client_id=GOOGLE_CLIENT_ID,
               client_secret=GOOGLE_CLIENT_SECRET,
               access_token_url=GOOGLE_TOKEN_URL,
               authorize_url=GOOGLE_AUTH_URL)
    data = {'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': GOOGLE_CALLBACK}

    google = service.get_auth_session(data=data, decoder=json.loads)
    response = google.get(GOOGLE_USER_INFO_URL)

    info ={}
    info['id'] = response.json()['id']
    info['email'] = response.json()['email']
    info['name'] = response.json()['name']
    info['picture'] = response.json()['picture']
    info['platform'] = platform

    session["info"] = json.dumps(info)

    return redirect(url_for("authorization.login_callback"), code=302)

def build_error_response(error_title, status, error_desc):
    jd = {"status_code:" : status, "error": error_title, "description": error_desc, "data": ""}
    resp = Response(response=json.dumps(jd), status=status, mimetype="application/json")
    return resp
