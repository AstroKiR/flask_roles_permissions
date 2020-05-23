from flask import render_template, redirect, request, flash, url_for
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from datetime import datetime

from app import app, db
from app.forms import LoginForm, CreateUserForm, EditUserForm, CreateRoleForm, EditRoleForm, ProfileForm
from app.models import User, Role, Area, Permission


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
@login_required
def users():
    users = User.query.all()
    return render_template('users/users.html', users=users)


@app.route('/create_user', methods=['GET', 'POST'])
@login_required
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
        flash('User successfully created')
        return redirect(url_for('users'))
    roles = Role.query.all()
    return render_template('users/create_user.html', form=create_user_form, roles=roles)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    roles = Role.query.all()
    user = User.query.get(user_id)
    user_roles = user.roles
    edit_user_form = EditUserForm(user.username, user.email)
    edit_flag = False

    if request.method == 'POST' and edit_user_form.validate_on_submit():
        user_roles_list = []
        for role in user_roles:
            user_roles_list.append(role.id)
        user_roles_set = set(user_roles_list)
        checked_roles_set = set(map(int, request.form.getlist('roles')))
        if user_roles_set ^ checked_roles_set:
            user.roles.clear()
            for new_role in checked_roles_set:
                user.roles.append(Role.query.get(new_role))
            edit_flag = True
        if edit_user_form.original_username != edit_user_form.data['username']:
            user.username = edit_user_form.data['username']
            edit_flag = True
        if edit_user_form.original_email != edit_user_form.data['email']:
            user.email = edit_user_form.data['email']
            edit_flag = True
        if edit_flag:
            user.creator_id = current_user.id
            user.updated_at = datetime.utcnow()
            db.session.commit()
            flash('User data successfully changed')
        return redirect(url_for('edit_user', user_id=user.id))
    elif request.method == 'GET':
        edit_user_form.username.data = user.username
        edit_user_form.email.data = user.email
    return render_template('users/edit_user.html', form=edit_user_form, roles=roles, user_roles=user_roles)


@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    if request.method == 'POST':
        user_id = request.form['user_id']
        user = User.query.get(user_id)
        user_name = user.username
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user_name} successfully deleted')
    return redirect(url_for('users'))


@app.route('/roles')
@login_required
def roles():
    roles = Role.query.all()
    return render_template('roles/roles.html', roles=roles)


@app.route('/create_role', methods=['GET', 'POST'])
@login_required
def create_role():
    create_role_form = CreateRoleForm()
    all_areas = Area.query.all()
    areas = {}
    for area in all_areas:
        areas[area.areaname] = Permission.query.filter_by(area_id=area.id).all()

    if request.method == 'POST' and create_role_form.validate_on_submit():
        permissions = list(map(int, request.form.getlist('permission')))
        role = Role(rolename=create_role_form.rolename.data, creator_id=current_user.id)
        for permission in permissions:
            role.permissions.append(Permission.query.get(permission))
        db.session.add(role)
        db.session.commit()
        return redirect(url_for('roles'))
    return render_template('roles/create_role.html', form=create_role_form, areas=areas)


@app.route('/edit_role/<int:role_id>', methods=['GET', 'POST'])
@login_required
def edit_role(role_id):
    edit_flag = False
    role = Role.query.get(role_id)
    edit_role_form = EditRoleForm(role.rolename)
    role_permissions_ids = []
    for permission in role.permissions:
        role_permissions_ids.append(permission.id)
    all_areas = Area.query.all()
    areas = {}
    for area in all_areas:
        perms = Permission.query.filter_by(area_id=area.id).all()
        areas[area.areaname] = []
        for perm in perms:
            checked = 'checked' if perm in role.permissions else ''
            areas[area.areaname].append({
                'id': perm.id,
                'ability': perm.ability,
                'checked': checked})
    if request.method == 'GET':
        edit_role_form.rolename.data = role.rolename
    elif request.method == 'POST' and edit_role_form.validate_on_submit():
        new_role_permissions_ids = []
        for new_permission in request.form.getlist('permission'):
            new_role_permissions_ids.append(int(new_permission))
        if set(role_permissions_ids) ^ set(new_role_permissions_ids):
            role.permissions.clear()
            for new_permission_id in new_role_permissions_ids:
                role.permissions.append(Permission.query.get(new_permission_id))
            edit_flag = True 
        if edit_role_form.original_rolename != edit_role_form.rolename.data:
            role.rolename = edit_role_form.rolename.data
            edit_flag = True
        if edit_flag:
            role.updated_at = datetime.utcnow()
            role.creator_id = current_user.id
            db.session.commit()
            flash('Role successfully changed')
            return redirect(url_for('edit_role', role_id=role.id))
    return render_template('roles/edit_role.html', form=edit_role_form, areas=areas)


@app.route('/delete_role', methods=['POST'])
@login_required
def delete_role():
    if request.method == 'POST':
        role_id = request.form['role_id']
        role = Role.query.get(role_id)
        role_name = role.rolename
        db.session.delete(role)
        db.session.commit()
        flash(f'Role {role_name} successfully deleted')
    return redirect(url_for('roles'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    profile_form = ProfileForm(current_user.username, current_user.email)
    if request.method == 'GET':
        profile_form.username.data = current_user.username
        profile_form.email.data = current_user.email
    if request.method == 'POST' and profile_form.validate_on_submit():
        user = User.query.get(current_user.id)
        edit_flag = False

        if profile_form.username.data != user.username:
            user.username = profile_form.username.data
            edit_flag = True

        if profile_form.email.data != user.email:
            user.email = profile_form.email.data
            edit_flag = True

        if profile_form.password.data:
            user.set_password(profile_form.password.data)
            edit_flag = True
        
        if edit_flag:
            db.session.commit()
            flash('Profile successfully changed')

    return render_template('profile.html', form=profile_form)