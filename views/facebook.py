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

facebook = Blueprint('facebook', __name__)

@facebook.route("/callback", methods = ['GET'])
def callback():
    if 'code' not in request.args:
        return build_error_response("Invalid Request", \
                                    400,\
                                    "User refused the platform authorization")
    platform = session['platform']
    code = request.args.get('code')
    service = OAuth2Service(
               name=platform,
               client_id=FACEBOOK_CLIENT_ID,
               client_secret=FACEBOOK_CLIENT_SECRET,
               access_token_url=FACEBOOK_TOKEN_URL,
               authorize_url=FACEBOOK_AUTH_URL)
    data = {'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': FACEBOOK_CALLBACK}

    facebook = service.get_auth_session(data=data)
    response = facebook.get(FACEBOOK_USER_INFO_URL + "?" + urllib.urlencode({"fields": "id,name,email,picturewidth(500).height(500)"})

    info ={}
    info['id'] = response.json()['id']
    info['email'] = response.json()['email']
    info['name'] = response.json()['name']
    info['picture'] = response.json()['picture']["data"]["url"]
    info['platform'] = platform

    session["info"] = json.dumps(info)

    return redirect(url_for("authorization.login_callback"), code=302)

def build_error_response(error_title, status, error_desc):
    jd = {"status_code:" : status, "error": error_title, "description": error_desc, "data": ""}
    resp = Response(response=json.dumps(jd), status=status, mimetype="application/json")
    return resp
