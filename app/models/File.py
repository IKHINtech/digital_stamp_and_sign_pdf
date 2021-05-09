from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash
from .Users import User, Role



class fileModel(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    filename = db.Column(db.String(128), unique=True)
    date_upload= db.Column(db.DateTime(), index=True, default=datetime.utcnow)
    page = db.Column(db.Integer)
    file = db.Column(db.LargeBinary())
    dosen1 = db.Column(db.String(128))
    dosen1_sign = db.Column(db.Boolean, default=False, nullable= False)
    dosen2 = db.Column(db.String(128))
    dosen2_sign = db.Column(db.Boolean, default=False, nullable= False)
    dosen3 = db.Column(db.String(128))
    dosen3_sign = db.Column(db.Boolean, default=False, nullable= False)
    sign = db.relationship('SignTable', backref='sign', lazy='dynamic')#child of user
    def __repr__(self):
        return "<fileModel %r>" % self.filename

class SignTable(db.Model):
    __tablename__ = 'file_signs'
    id = db.Column(db.Integer, primary_key = True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'))
    file = db.Column(db.LargeBinary())
    sign1 = db.Column(db.String(128))
    sign2 = db.Column(db.String(128))
    sign3 = db.Column(db.String(128))
    sign1_date= db.Column(db.DateTime(), index=True)
    sign2_date= db.Column(db.DateTime(), index=True)
    sign3_date= db.Column(db.DateTime(), index=True)
    date= db.Column(db.DateTime(), index=True, default=datetime.utcnow)
    # file_asli = db.relationship('fileModel', backref='source', lazy='dynamic',
    #                                     primaryjoin="and_(SignTable.file_id==fileModel.id)")#child
    
    def __repr__(self):
        return "<SignTable %r>" % self.file_id

class Skripsi(db.Model):
    __tablename__ = 'skripsi'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    filename = db.Column(db.String(128), unique=True)
    file = db.Column(db.LargeBinary())
    path = db.Column(db.String(128))
    date_upload= db.Column(db.DateTime(), index=True, default=datetime.utcnow)
    page = db.Column(db.Integer)
    pem1 = db.Column(db.String(128))
    pem2 = db.Column(db.String(128))
    peng1 = db.Column(db.String(128))
    peng2 = db.Column(db.String(128))
    prodi = db.Column(db.String(128))
    dekan = db.Column(db.String(128))
    pem1_sign = db.Column(db.Boolean, default=False, nullable= False)
    pem2_sign = db.Column(db.Boolean, default=False, nullable= False)
    peng1_sign = db.Column(db.Boolean, default=False, nullable= False)
    peng2_sign = db.Column(db.Boolean, default=False, nullable= False)
    prodi_sign = db.Column(db.Boolean, default=False, nullable= False)
    dekan_sign = db.Column(db.Boolean, default=False, nullable= False)
    pem1_date = db.Column(db.DateTime(), index=True)
    pem2_date = db.Column(db.DateTime(), index=True)
    peng1_date = db.Column(db.DateTime(), index=True)
    peng2_date = db.Column(db.DateTime(), index=True)
    prodi_date = db.Column(db.DateTime(), index=True)
    dekan_date = db.Column(db.DateTime(), index=True)
    done = db.Column(db.Boolean, default=False, nullable= False)
    progres = db.Column(db.Integer, default = 0)
    
    def __repr__(self):
        return  "<Skripsi %r>" % self.filename

class temp(db.Model):
    __tablename__ = 'file_temp'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    filename = db.Column(db.String(128), unique=True)
    file = db.Column(db.LargeBinary())
    path = db.Column(db.String(128))
    date_upload= db.Column(db.DateTime(), index=True, default=datetime.utcnow)
    page = db.Column(db.Integer)
    pem1 = db.Column(db.String(128))
    pem2 = db.Column(db.String(128))
    peng1 = db.Column(db.String(128))
    peng2 = db.Column(db.String(128))
    prodi = db.Column(db.String(128))
    dekan = db.Column(db.String(128))
    pem1_path = db.Column(db.Boolean, default=False, nullable= False)
    pem2_path = db.Column(db.Boolean, default=False, nullable= False)
    peng1_path = db.Column(db.Boolean, default=False, nullable= False)
    peng2_path = db.Column(db.Boolean, default=False, nullable= False)
    prodi_path = db.Column(db.Boolean, default=False, nullable= False)
    dekan_path = db.Column(db.Boolean, default=False, nullable= False)
    
    def __repr__(self):
        return  "<Skripsi %r>" % self.filename

