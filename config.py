import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'B1sm1ll4H'
    SQLALCHEMY_DATABASE_URI = \
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CORS_HEADERS = 'Content-Type'
    UPLOAD_FOLDER = os.path.join(basedir, "app/static/uploads")
    UPLOAD_FILE = os.path.join(basedir, "static/uploads/pdf")
    CERTIFICATE = os.path.join(basedir, "app/static/uploads/certificate")
    TEMPLATE_FOLDER = os.path.join(basedir, "app/static/uploads/template")
    SIGNATURE_FILE = os.path.join(basedir, "app/static/uploads/signature")
    ALLOWED_EXTENSIONS = ['pdf','png','jpg','jpeg']
    MAX_CONTENT_LENGTH = 100 * 1024 *1024
    JWT_SECRET_KEY = str(os.environ.get('JWT_SECRET'))
    DIGISIGN_ADMIN = os.environ.get('DIGISIGN_ADMIN')