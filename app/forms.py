from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, BooleanField 
from wtforms.validators import ValidationError, DataRequired, Email

from app.models import User, Role


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Create')

    def validate_username(self, field):
        user = User.query.filter_by(username=field.data).all()
        if user:
            raise ValidationError('This username already exists.')

    def validate_email(self, field):
        email = User.query.filter_by(email=field.data).all()
        if email:
            raise ValidationError('This email already exists.')


class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Save')

    def __init__(self, original_username, original_email, *args, **kwargs):
        super(EditUserForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=self.email.data).first()
            if user is not None:
                raise ValidationError('Please use a different email.')


class CreateRoleForm(FlaskForm):
    rolename = StringField('Rolename', validators=[DataRequired()])
    submit = SubmitField('Save')

    def validate_rolename(self, field):
        role = Role.query.filter_by(rolename=field.data).all()
        if role:
            raise ValidationError('This rolename already exists.')
