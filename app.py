################################################
# Author: Bruno Silva - brunomiguelsilva@ua.pt #
################################################

from flask import Flask
from flask_restful import Api, Resource

from settings import *
from views.authorization import authorization
from views.google import google
from views.facebook import facebook

app = Flask(__name__)

app.secret_key = SECRET_KEY

app.register_blueprint(authorization)
app.register_blueprint(google, url_prefix='/google')
app.register_blueprint(facebook, url_prefix='/facebook')

if __name__ == '__main__':
    app.run(port=PORT, host=ALLOWED_HOSTS)
