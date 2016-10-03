
from settings import *

from flask import Flask
from flask_restful import reqparse, abort, Api, Resource

from views.google import google
from views.authorization import authorization

app = Flask(__name__)



app.register_blueprint(google, url_prefix='/google')
app.register_blueprint(authorization)

if __name__ == '__main__':
    app.run(port=PORT, host=ALLOWED_HOSTS)

