import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'B1sm1ll4H'
    SQLALCHEMY_DATABASE_URI = \
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CORS_HEADERS = 'Content-Type'

    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in \
        ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'hrisaproject@gmail.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD','hrisati17d7')

    UPLOAD_FOLDER = os.path.join(basedir, "app/static/uploads/photos")
    UPLOAD_FILE = os.path.join(basedir, "app/static/uploads/pdf")
    TEMP_FILE = os.path.join(basedir, "app/static/uploads/pdf/temp")
    CERTIFICATE = os.path.join(basedir, "app/static/uploads/certificate")
    TEMPLATE_FOLDER = os.path.join(basedir, "app/static/uploads/template")
    SIGNATURE_FILE = os.path.join(basedir, "app/static/uploads/signature")
    ALLOWED_EXTENSIONS = ['pdf','png','jpg','jpeg']
    MAX_CONTENT_LENGTH = 100 * 1024 *1024
    JWT_SECRET_KEY = str(os.environ.get('JWT_SECRET'))
    DIGISIGN_ADMIN = os.environ.get('DIGISIGN_ADMIN')
    DIGISIGN_MAIL_SUBJECT_PREFIX = '[UPB - DIGISIGN]'
    DIGISIGN_MAIL_SENDER ='UPB - DIGISIGN <helpdesk@digisign.pelitabangsa.ac.id>'