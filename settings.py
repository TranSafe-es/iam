import os

BASE_DIR = os.path.dirname(os.path.realpath(__file__))

SQL_CONNECTION = 'postgresql://es:es-test@192.168.0.200:5432/usermanagement'

ALLOWED_HOSTS = "0.0.0.0"

HOST = "192.168.0.200"
PORT = 5001

# REDIS_HOST = "localhost"
# REDIS_PORT = 6379

LOGIN_CALLBACK = "http://" + HOST + ":" + str(PORT) + "/login_callback"
SIGNUP_CALLBACK = "http://" + HOST + ":" + str(PORT) + "/signup_callback"
ADD_SERVICE_CALLBACK = "http://" + HOST + ":" + str(PORT) + "/add_service_callback"

GOOGLE_CLIENT_ID = "293658887975-550p1edh55ig1vp9gfgeof5ppmmkc8kp.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "jzfFz42h68-u9BUQpEpOphgZ"

GITHUB_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
GITHUB_TOKEN_URL = "https://accounts.google.com/o/oauth2/token"
GITHUB_USER_INFO_URL = "https://api.github.com/user"



TOKEN_DURATION = 600
