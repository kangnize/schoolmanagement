# app/routes.py
from flask import render_template, url_for, flash, redirect, Blueprint, request
from app import db, bcrypt
from app.forms import RegistrationForm, LoginForm, EditForm
from app.models import User
from flask_login import login_user, current_user, logout_user, login_required

bp = Blueprint('main', __name__)

@bp.route("/")
@bp.route("/home")
def home():
    return render_template('home.html')

@bp.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.base'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', title='Register', form=form)

@bp.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.base'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('You have been logged in successfully.', 'success')
            return redirect(next_page) if next_page else redirect(url_for('main.account'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('main.home'))

# Existing routes...



@bp.route("/account")
@login_required
def account():
   return render_template('account.html', title='Account', user=current_user)

@bp.route("/account/edit", methods=['GET', 'POST'])
@login_required
def edit():
    form =EditForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.password.data:
            current_user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('main.account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('edit.html', title='Edit Account', form=form)

@bp.route("/account/delete", methods=['POST'])
@login_required
def delete_account():
    db.session.delete(current_user)
    db.session.commit()
    flash('Your account has been deleted!', 'success')
    return redirect(url_for('main.home'))