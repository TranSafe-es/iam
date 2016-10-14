import os

BASE_DIR = os.path.dirname(os.path.realpath(__file__))

SQL_CONNECTION = 'postgresql://es:es-test@192.168.0.190:5432/usermanagement'

ALLOWED_HOSTS = "0.0.0.0"

HOST = "192.168.0.190"
PORT = 5001

TOKEN_DURATION = 3600

SECRET_KEY = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'


FACEBOOK_CLIENT_ID = "1132877063463236"
FACEBOOK_CLIENT_SECRET = "ebbb5ff7656b43ec91f03ba4175aaa5f"
FACEBOOK_AUTH_URL = "https://graph.facebook.com/oauth/authorize"
FACEBOOK_TOKEN_URL = "https://graph.facebook.com/oauth/access_token"
FACEBOOK_USER_INFO_URL = "https://graph.facebook.com/v2.8/me/"
FACEBOOK_CALLBACK = "http://bsilvr.duckdns.org:5368/facebook/callback"

GOOGLE_CLIENT_ID = "293658887975-550p1edh55ig1vp9gfgeof5ppmmkc8kp.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "jzfFz42h68-u9BUQpEpOphgZ"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL = "https://accounts.google.com/o/oauth2/token"
GOOGLE_USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json"
GOOGLE_CALLBACK = "http://bsilvr.duckdns.org:5368/google/callback"
