from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, BooleanField 
from wtforms.validators import ValidationError, DataRequired, Email

from app.models import User


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