from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_moment import Moment
from flask_cors import CORS
from flask_mail import Mail

app = Flask(__name__, static_folder="static")
app.config.from_object(Config)
db = SQLAlchemy(app)
moment = Moment(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
mail = Mail()
# login_manager.refresh_view = 'login'
# login_manager.needs_refresh_message = (u"Session timedout, please re-login")
# login_manager.needs_refresh_message_category = "info"
login_manager.init_app(app)
mail.init_app(app)
migrate = Migrate(app, db, render_as_batch= True)
cors = CORS(app)


from app import routes
from app import errors
from app.models import File, Users