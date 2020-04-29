from flask import render_template, redirect, request, flash, url_for
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse

from app import app, db
from app.forms import LoginForm, CreateUserForm
from app.models import User, Role


@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/users')
def users():
    users = User.query.all()
    return render_template('users/users.html', users=users)


@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    create_user_form = CreateUserForm()
    if request.method == 'POST' and create_user_form.validate_on_submit():
        user = User(
            username=create_user_form.data['username'], 
            email=create_user_form.data['email'],
            creator_id = current_user.id)
        user.set_password('test')
        for role in request.form.getlist('roles'):
            user.roles.append(Role.query.get(role))
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('users')) 
    roles = Role.query.all()
    return render_template('users/create_user.html', form=create_user_form, roles=roles)


@app.route('/roles')
def roles():
    return render_template('roles/roles.html')
