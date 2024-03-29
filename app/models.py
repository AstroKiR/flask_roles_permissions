from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import db, login


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


role_permission = db.Table('role_permission',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'), primary_key=True)
)


user_role = db.Table('user_role',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_at = db.Column(db.DateTime())
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=True)
    created_users = db.relationship('User', backref=db.backref('creator', remote_side='User.id'))
    created_roles = db.relationship('Role', backref=db.backref('creator'))
    roles = db.relationship('Role', secondary=user_role, lazy='subquery', backref=db.backref('users', lazy=True))

    def __repr__(self):
        return '<User {}>'.format(self.username) 

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Area(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    areaname = db.Column(db.String(64), unique=True)
    permissions = db.relationship('Permission', backref=db.backref('aria'))

    def __repr__(self):
        return '<Aria {}>'.format(self.areaname) 


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ability = db.Column(db.String(64))
    area_id = db.Column(db.Integer, db.ForeignKey('area.id'), nullable=False)

    def __repr__(self):
        return f'<Permission {Area.query.get(self.area_id).areaname}:{self.ability}>' 
    

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rolename = db.Column(db.String(64), unique=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_at = db.Column(db.DateTime())
    permissions = db.relationship('Permission', secondary=role_permission, lazy='subquery', backref=db.backref('roles', lazy=True))

    def __repr__(self):
        return '<Role {}>'.format(self.rolename) 
