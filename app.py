################################################
# Author: Bruno Silva - brunomiguelsilva@ua.pt #
################################################

from flask import Flask, render_template, url_for
from flask_restful import Api, Resource

from settings import *
from views.authorization import authorization
from views.google import google
from views.facebook import facebook
from views.apps import apps

app = Flask(__name__)

app.secret_key = SECRET_KEY

app.register_blueprint(authorization)
app.register_blueprint(apps, url_prefix='/apps')
app.register_blueprint(google, url_prefix='/google')
app.register_blueprint(facebook, url_prefix='/facebook')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(port=PORT, host=ALLOWED_HOSTS, debug=True)
