from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField
from wtforms.validators import Email, DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', id='username_login', validators=[DataRequired()])
    password = PasswordField('Password', id='pwd_login', validators=[DataRequired()])


class CreateAccountForm(FlaskForm):
    username = StringField('Username', id='username_create', validators=[DataRequired()])
    email = StringField('Email', id='email_create', validators=[DataRequired(), Email()])
    password = PasswordField('Password' , id='pwd_create', validators=[DataRequired()])
    confirmpassword = PasswordField('ConfirmPassword' , id='confirm_pwd_create', validators=[DataRequired()])
    firstname = StringField('Firstname', id='firstname_create', validators=[DataRequired()])
    lastname = StringField('Lastname', id='lastname_create', validators=[DataRequired()])
    

class PasswordRecoveryForm(FlaskForm):
    username = StringField('Username', id='username_create', validators=[DataRequired()])
    email = StringField('Email', id='email_create', validators=[DataRequired(), Email()])


class ChangePasswordRecoveryForm(FlaskForm):
    username = StringField('Username', id='username', validators=[DataRequired()])
    token = StringField('Token', id='token', validators=[DataRequired()])
    newpassword = PasswordField('NewPassword', id='newpassword_change', validators=[DataRequired()])
    confirmnewpassword = PasswordField('ConfirmNewPassword' , id='confirm_pwd_change', validators=[DataRequired()])


class CreateClientForm(FlaskForm):
    clientname = StringField('Clientname', id='clientname_create', validators=[DataRequired()])
    email = StringField('Email', id='email_create', validators=[DataRequired(), Email()])
    firstname = StringField('Firstname', id='firstname_create', validators=[DataRequired()])
    lastname = StringField('Lastname', id='lastname_create', validators=[DataRequired()])
    city = StringField('City', id='City_create', validators=[DataRequired()])


class VulnerableCreateClientForm(FlaskForm):
    clientname = StringField('Clientname', id='clientname_create', validators=[DataRequired()])
    email = StringField('Email', id='email_create', validators=[DataRequired()])
    firstname = StringField('Firstname', id='firstname_create', validators=[DataRequired()])
    lastname = StringField('Lastname', id='lastname_create', validators=[DataRequired()])
    city = StringField('City', id='City_create', validators=[DataRequired()])


class ChangePasswordForm(FlaskForm):
    currentpassword = PasswordField('CurrentPassword', id='currentpassword_change', validators=[DataRequired()])
    newpassword = PasswordField('NewPassword', id='newpassword_change', validators=[DataRequired()])
    confirmnewpassword = PasswordField('ConfirmNewPassword' , id='confirm_pwd_change', validators=[DataRequired()])
