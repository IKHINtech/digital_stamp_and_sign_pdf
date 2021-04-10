import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ini sangat rahasia'
    SQLALCHEMY_DATABASE_URI = \
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CORS_HEADERS = 'Content-Type'
    UPLOAD_FOLDER = os.path.join(basedir, "static/uploads")
    ALLOWED_EXTENSIONS = {'pdf'}
    MAX_CONTENT_LENGTH = 100 * 1024 *1024
    JWT_SECRET_KEY = str(os.environ.get('JWT_SECRET'))
    FLASKY_ADMIN = os.environ.get('HRISA_ADMIN')