from re import U
from flask import jsonify, render_template, redirect, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from app import db, login_manager
from app.base import blueprint
from app.base.forms import ChangePasswordForm, LoginForm, CreateAccountForm, CreateClientForm, PasswordRecoveryForm, ChangePasswordRecoveryForm, VulnerableCreateClientForm
from app.base.models import User, Client, Passwords
from app.base.util import hash_pass, verify_pass, verify_pass_complexity, verify_pass_length, verify_pass_with_dictionary, email_sender
import json
from datetime import datetime
import string
import random
from sqlalchemy import desc


@blueprint.route('/',methods=['GET'])
def route_default():
    return render_template('home.html',name="home")



@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if 'login' in request.form:
        username = request.form['username']
        password = request.form['password']
        # check if user exists
        user = User.query.filter_by(username=username).first()
        # check the password
        if user:
            with open('config.json') as json_file:
                configData = json.load(json_file)
            maxretries = configData['maxRetries']
            numretries = user.retries
            if user.locked:
                return render_template('accounts/login.html', msg='User locked!', form=login_form)
            elif verify_pass(password, user.password):
                login_user(user)
                user.retries = 0
                db.session.commit()
                return redirect(url_for('home_blueprint.index'))
            elif numretries < maxretries:
                user.retries = numretries + 1
                db.session.commit()
                return render_template('accounts/login.html', msg='Wrong password, please retry ({} retries left).'.format(maxretries - numretries), form=login_form)
            elif numretries >= maxretries:
                user.locked = True
                db.session.commit()
                return render_template('accounts/login.html', msg='User locked!', form=login_form)
        else:
            return render_template('accounts/login.html', msg='User does not exists, please retry.', form=login_form)
    
    # check if user logged-in and redirect to main page
    if not current_user.is_authenticated:
        if 'msg' in request.args:
            return render_template('accounts/login.html', msg=request.args['msg'], form=login_form)
        else:
            return render_template('accounts/login.html', form=login_form)
    return redirect(url_for('home_blueprint.index'))


@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirmpassword = request.form['confirmpassword']
        firstname = request.form['firstname']
        lastname = request.form['lastname']

        # Loading config file
        with open('config.json') as json_file:
            configData = json.load(json_file)
        minLength = configData['minLength']
        dictionary = configData['dictionary']
        complexPassword =  configData['complexPassword']

        # Check usename exists
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('accounts/register.html', msg='Username already registered',success=False, form=create_account_form)
        # Check email exists
        user = User.query.filter_by(email=email).first()
        if user:
            return render_template('accounts/register.html', msg='Email already registered', success=False, form=create_account_form)

        # Verify password requirements:
        if password != confirmpassword:
            return render_template('accounts/register.html', msg='Password confirmation does not match', success=False, form=create_account_form)
        # Verify minimum lenght
        if verify_pass_length (password, minLength ):
            return render_template('accounts/register.html', msg="Your password must have at least %d characters"%(minLength) , success=False, form=create_account_form)
        # Verify complexity
        if complexPassword:
            if verify_pass_complexity(password):
                return render_template('accounts/register.html', msg="Your password must have at least 1 upper case, lower case, numeric, and special character", success=False, form=create_account_form)
        # Verify dictionary 
        dictionaryResult = verify_pass_with_dictionary(password,dictionary)
        if dictionaryResult != "0":
            return render_template('accounts/register.html', msg=("Password can't include : '%s'"%(dictionaryResult)) , success=False, form=create_account_form)

        # Create the user write to DBs and send to login screen
        user = User(username=username, password=password, firstname=firstname, lastname=lastname, email=email)
        db.session.add(user)
        passlog = Passwords(username=user.username, password=password)
        db.session.add(passlog)
        db.session.commit()
        return redirect(url_for('base_blueprint.login', msg="User created successfully, please login"))
    elif current_user.is_active:
            return redirect(url_for('home_blueprint.index'))
    else:
        return render_template('accounts/register.html', form=create_account_form)


@blueprint.route('/changepassword', methods=['GET', 'POST'])
@login_required
def changepassword():
    change_password_form = ChangePasswordForm(request.form)
    if not current_user.is_authenticated:
        return redirect(url_for('base_blueprint.route_default'))

    if 'changepassword' in request.form:
        user = User.query.filter_by(username=current_user.username).first()
        currentpassword = request.form['currentpassword']
        newpassword = request.form['newpassword']
        confirmnewpassword = request.form['confirmnewpassword']
        
        # Loading config file
        with open('config.json') as json_file:
            configData = json.load(json_file)
        minLength = configData['minLength']
        dictionary = configData['dictionary']
        complexPassword =  configData['complexPassword']
        history_number = configData['history']

        # Verify form passwords:
        if not(verify_pass(currentpassword, user.password)):
            return render_template('accounts/change_password.html', segment='index', msg='Current Password Wrong!', form=change_password_form)
        if newpassword != confirmnewpassword:
            return render_template('accounts/change_password.html', segment='index', msg='Password confirmation does not match', success=False, form=change_password_form)
        if newpassword == currentpassword:
            return render_template('accounts/change_password.html', segment='index', msg='New password must be diffrent from current one', success=False, form=change_password_form)
        
        # Verify password requirements
        # Verify minimum lenght
        if verify_pass_length (newpassword, minLength ):
            return render_template('accounts/change_password.html', segment='index', msg="Your password must have at least %d characters"%(minLength) , success=False, form=change_password_form)
        # Verify complexity
        if complexPassword:
            if verify_pass_complexity(newpassword):
                return render_template('accounts/change_password.html', segment='index', msg="Your password must have at least 1 upper case, lower case, numeric, and special character", success=False, form=change_password_form)
        # Verify dictionary 
        dictionaryResult = verify_pass_with_dictionary(newpassword,dictionary)
        if dictionaryResult != "0":
            return render_template('accounts/change_password.html', segment='index', msg=("Password can't include : '%s'"%(dictionaryResult)) , success=False, form=change_password_form)
        # Verify password history
        password_history = Passwords.query.filter_by(username=current_user.username).order_by(desc(Passwords.id)).limit(history_number).all()
        for password_iteration in password_history:
            if verify_pass(newpassword, password_iteration.password):
                return render_template('accounts/change_password.html', segment='index', msg=("Password must be diffrent from last '%d' passwords"%(history_number)) , success=False, form=change_password_form)

        # Update password on DBs and require user login
        user.password = hash_pass(newpassword)
        passlog = Passwords(username=user.username, password=newpassword)
        db.session.add(passlog)
        db.session.commit()
        logout_user()
        return redirect(url_for('base_blueprint.login', msg="Password updated successfully, please login"))
    else:
        return render_template('accounts/change_password.html', segment='index', form=change_password_form)


@blueprint.route('/passwordrecovery', methods=['GET', 'POST'])
def passwordrecovery():
    password_recovery_form = PasswordRecoveryForm(request.form)
    if 'sendtoken' in request.form:
        username = request.form['username']
        email = request.form['email']
        user = User.query.filter_by(username=username).first()
        if user and (user.email == email):
            # Generates random token and takes current date
            all_chars = string.ascii_letters + string.digits + string.punctuation
            token = ''.join(random.choices(all_chars, k=10))
            current_date = datetime.now()
            user.token = token
            user.token_date = current_date
            db.session.commit()
            # Send the token to the user email
            print(token)
            message = """\
            [CommunicationLTD] Password Recovery

            Your token for the next hour is: {} """.format(token)
            email_sender(email, message)
            return redirect(url_for('base_blueprint.changepasswordrecovery', msg="Please check your email for the recovery token"))
        else:
            return render_template('accounts/password_recovery.html', msg="User or Email does not match, please retry.", form=password_recovery_form)
    if current_user.is_active:
        return redirect(url_for('home_blueprint.index'))
    return render_template('accounts/password_recovery.html', form=password_recovery_form)


@blueprint.route('/changepasswordrecovery', methods=['GET', 'POST'])
def changepasswordrecovery():
    change_password_recovery_form = ChangePasswordRecoveryForm(request.form)
    if 'changepasswordrecovery' in request.form:
        username = request.form['username']
        token = request.form['token']
        newpassword = request.form['newpassword']
        confirmnewpassword = request.form['confirmnewpassword']

        with open('config.json') as json_file:
            configData = json.load(json_file)
        minLength = configData['minLength']
        dictionary = configData['dictionary']
        complexPassword =  configData['complexPassword']
        tokenExpirationSeconds = configData['tokenExpirationSeconds']
        history_number = configData['history']
        
        user = User.query.filter_by(username=username).first()
        timedelta = (datetime.now() - user.token_date).total_seconds()
        # validate token and time delta
        if (user.token != token) or (timedelta > tokenExpirationSeconds):
            return render_template('accounts/change_password_recovery.html', msg='Token is invalid or expired, please retry or request a new token', success=False, form=change_password_recovery_form)
        
        # password requirments
        if newpassword != confirmnewpassword:
            return render_template('accounts/change_password_recovery.html', msg='Password confirmation does not match', success=False, form=change_password_recovery_form)
        # Verify minimum lenght
        if verify_pass_length (newpassword, minLength ):
            return render_template('accounts/change_password_recovery.html', msg="Your password must have at least %d characters"%(minLength) , success=False, form=change_password_recovery_form)
        # Verify complexity
        if complexPassword:
            if verify_pass_complexity(newpassword):
                return render_template('accounts/change_password_recovery.html', msg="Your password must have at least 1 upper case, lower case, numeric, and special character", success=False, form=change_password_recovery_form)
        # Verify dictionary 
        dictionaryResult = verify_pass_with_dictionary(newpassword,dictionary)
        if dictionaryResult != "0":
            return render_template('accounts/change_password_recovery.html', msg=("Password can't include : '%s'"%(dictionaryResult)) , success=False, form=change_password_recovery_form)
        # Verify password history
        password_history = Passwords.query.filter_by(username=username).order_by(desc(Passwords.id)).limit(history_number).all()
        for password_iteration in password_history:
            if verify_pass(newpassword, password_iteration.password):
                return render_template('accounts/change_password_recovery.html', segment='index', msg=("Password must be diffrent from last '%d' passwords"%(history_number)) , success=False, form=change_password_recovery_form)

        # Update password on DB and require user login
        user.password = hash_pass(newpassword)
        passlog = Passwords(username=user.username, password=newpassword)
        db.session.add(passlog)
        user.token = ''
        passlog = Passwords(username=user.username, password=newpassword)
        db.session.add(passlog)
        db.session.commit()
        logout_user()
        return redirect(url_for('base_blueprint.login', msg="Password updated successfully, please login"))
    if current_user.is_active:
        return redirect(url_for('home_blueprint.index'))
    return render_template('accounts/change_password_recovery.html', form=change_password_recovery_form)


@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('base_blueprint.route_default'))


@blueprint.route('/registerclient', methods=['GET', 'POST'])
@login_required
def registerclient():
    create_client_form = CreateClientForm(request.form)
    if not current_user.is_authenticated:
        return redirect(url_for('base_blueprint.route_default'))
    if 'clientregister' in request.form:
        clientname = request.form['clientname']
        email = request.form['email']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        city = request.form['city']

        # Check if client email exists
        client = Client.query.filter_by(email=email).first()
        if client:
            return render_template('clients/registerclient.html', msg='Email already registered', segment='index', success=False, form=create_client_form)

        # Create the client and send to clients list screen
        client = Client(clientname=clientname, firstname=firstname, lastname=lastname, email=email, city=city)
        db.session.add(client)
        db.session.commit()
        return redirect(url_for('base_blueprint.clients'))
    else:
        return render_template('clients/registerclient.html', segment='index', form=create_client_form)


@blueprint.route('/vulnerableregisterclient', methods=['GET', 'POST'])
@login_required
def vulnerableregisterclient():
    #################
    # Usage:
    # enter in the email: ' ; DELETE FROM Client;--
    # it will delete all the data in the Client table - data loss.
    ################
    create_client_form = VulnerableCreateClientForm(request.form)
    if not current_user.is_authenticated:
        return redirect(url_for('base_blueprint.route_default'))
    if 'clientregister' in request.form:
        clientname = request.form['clientname']
        email = request.form['email']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        city = request.form['city']

        # Check if client email exists using a raw query - vulnerable
        sql_query = "SELECT top(1) * FROM Client WHERE email='{}';".format(email)
        client = db.session.execute(sql_query)
        if client.first():
            return render_template('clients/vulnerableregisterclient.html', msg='Email already registered', segment='index', success=False, form=create_client_form)

        # Create the client and send to clients list screen
        client = Client(clientname=clientname, firstname=firstname, lastname=lastname, email=email, city=city)
        db.session.add(client)
        db.session.commit()
        return redirect(url_for('base_blueprint.clients'))
    else:
        return render_template('clients/vulnerableregisterclient.html', segment='index', form=create_client_form)


@blueprint.route('/clients', methods=['GET', 'POST'])
@login_required
def clients():
    if not current_user.is_authenticated:
        return redirect(url_for('base_blueprint.route_default'))
    if request.method == "GET":
        return render_template("clients/clients.html", query=Client.query.all(), segment='index')


@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('page-403.html'), 403


@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('page-403.html'), 403


@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('page-404.html'), 404


@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('page-500.html'), 500
