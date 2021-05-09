from app import db, login_manager
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin
from app import app
import hashlib

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default_role_name = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')#child of user

    def __init__(self, **kwargs):
        super(Role,self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions=0

    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permission.USER, Permission.READ, Permission.WRITE],
            'Dosen': [Permission.USER, Permission.READ,
                          Permission.WRITE, Permission.SIGN],
            'Prodi':[Permission.USER, Permission.READ,
                          Permission.WRITE, Permission.SIGN, Permission.PRODI],
            'Dekan':[Permission.USER, Permission.READ,
                          Permission.WRITE, Permission.SIGN, Permission.PRODI, Permission.DEKAN],
            'Administrator': [Permission.USER, Permission.READ,
                              Permission.WRITE, Permission.SIGN,Permission.PRODI,Permission.DEKAN,
                              Permission.ADMIN],
        }
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default_role_name = (role.name == default_role)
            db.session.add(role)
        db.session.commit()

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm
        
    def __repr__(self):
        return '<Role %r>' % self.name


class Permission:
    USER = 1
    READ = 2
    WRITE = 4
    SIGN = 8
    PRODI = 16
    DEKAN = 32
    ADMIN = 64


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    nomor = db.Column(db.String(64), unique=True, index=True)
    name = db.Column(db.String(64), index=True)
    p_profile = db.Column(db.String(128), index=True)
    signature = db.Column(db.String(128), index=True)
    sertifikat = db.Column(db.String(128), index=True)
    key_sertifikat = db.Column(db.String(128), index=True)
    password_sertifikat = db.Column(db.String(128))
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    # avatar_hash = db.Column(db.String(32))
    doc =  db.relationship('fileModel', backref='doc', lazy='dynamic')#child of doc
    skrip =  db.relationship('Skripsi', backref='skrip', lazy='dynamic')#child of doc

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == app.config['DIGISIGN_ADMIN']: 
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default_role_name=True).first()
        # if self.email is not None and self.avatar_hash is None:
        #     self.avatar_hash = self.gravatar_hash()

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # def gravatar_hash(self):
    #     return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()

    # def gravatar(self, size=100, default='identicon', rating='g'):
    #     url = 'https://secure.gravatar.com/avatar'
    #     hash = self.avatar_hash or self.gravatar_hash()
    #     return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
    #         url=url, hash=hash, size=size, default=default, rating=rating)

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)

    def as_dict(self):
        return {'name': self.name}

    def __repr__(self):
        return '<User %r>' % self.name

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))