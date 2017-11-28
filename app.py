#!/usr/bin/env python
# -*- coding: utf-8 -*-
import config

from flask import Flask, flash, url_for, redirect, render_template, request,Response, make_response
import flask_admin as admin
from flask_admin import helpers, expose
import flask_login as login
from flask_login.utils import login_required
from flask_login.mixins import AnonymousUserMixin
from flask_admin import BaseView

#password
from werkzeug.security import generate_password_hash, check_password_hash

#db
from flask_sqlalchemy import SQLAlchemy
from flask_admin.contrib import sqla
from sqlalchemy.orm import joinedload_all

#form
from wtforms import form, fields, StringField, PasswordField, SubmitField, validators
from wtforms.validators import Required, Email

#tools
import json, collections, traceback
import logging

logging.basicConfig(filename='functional.log',level=logging.WARNING,
                    format='[%(name)s] %(message)s')
logger = logging.getLogger('Functional')
# logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

# Create Flask application
app = Flask(__name__)

# Create dummy secrey key so we can use sessions
app.secret_key = 'litonqiuyu8290'

#local
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://'+config.mysqlUser+':'+config.mysqlPassword+'@localhost/app_weekreport'
db = SQLAlchemy(app)

# Guest user
class Anonymous(AnonymousUserMixin):
    def is_admin(self):
        return False
    def has_children(self):
        return False

# Create user model.
class User(db.Model):
    extend_existing=True
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable = False, unique = True)
    name = db.Column(db.String(100), nullable = False)
    isAdmin = db.Column(db.Boolean, default=False)
    password = db.Column(db.String(160), nullable = False)
    is_authenticated = True
    is_active = True
    is_anonymous = False
    def is_admin(self):
        return self.isAdmin
    def get_id(self):
        return self.id
    def has_children(self):
        node = db.session.query(TreeNode).\
                    options(joinedload_all("children", "children",
                                            "children", "children")).\
                    filter(TreeNode.name == self.name).\
                    first()
        if node:
            if len(node.children) >= 1:
                return True
        else:
            return False
    def __unicode__(self):
        return self.username

# Create user model.
class Event(db.Model):
    extend_existing=True
    id = db.Column(db.Integer, primary_key=True)
    userID = db.Column(db.Integer)
    date = db.Column(db.Date)
    content = db.Column(db.TEXT)

class TreeNode(db.Model):
    __tablename__ = 'tree'
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey(id))
    name = db.Column(db.String(100), nullable=False)

    children = db.relationship("TreeNode",

                        # many to one + adjacency list - remote_side
                        # is required to reference the 'remote'
                        # column in the join condition.
                        backref=db.backref("parent", remote_side=id),
                    )

    def __repr__(self):
        #This value also shows in UI tree node
        return self.name;


    def dump(self):
        d = collections.OrderedDict()
        d['id'] = str(self.id)
        d['label'] = self.name

        subList = []
        for child in self.children:
            subList.append(child.dump())
        if subList != []:
            d['children'] = subList
        return d


# manager = User()
# manager.name = 'manager'
# manager.email = 'manager@test.com'
# manager.isAdmin = True
# manager.password = generate_password_hash('password2017')
#
# employee = User()
# employee.name = 'employee1'
# employee.email = 'employee1@test.com'
# employee.isAdmin = False
# employee.password = generate_password_hash('password2017')
#
# db.create_all()
# db.session.add(manager)
# db.session.add(employee)
# db.session.commit()


# Define login and registration forms (for flask-login)
class LoginForm(form.Form):
    email = StringField(u'Email', [Required(message=u'*Required'), Email(message=u'Invalid email')])#todo css
    password = PasswordField(u'Password', [Required(message=u'*Required')])

    def validate(self):
        rv = form.Form.validate(self)
        if not rv:
            return False

        user = db.session.query(User).filter_by(email=self.email.data).first()

        if user is None:
            self.email.errors.append(u'Email or password is wrong')
            return False

        # we're comparing the plaintext pw with the the hash from the db
        if not check_password_hash(user.password, self.password.data):
        # to compare plain text passwords use
        # if user.password != self.password.data:
            self.password.errors.append(u'Email or password is wrong')
            return False
        self.user = user
        return True

class ChangeEmailForm(form.Form):
    email = StringField(u'email', [Required(message=u'Please input your new email'), Email(message=u'Invalid email')])#todo css
    def validate(self):
        rv = form.Form.validate(self)
        if not rv:
            return False
        return True

class ChangePasswordForm(form.Form):
    password = PasswordField(u'Password', [Required(message=u'Please input your new password')])
    def validate(self):
        rv = form.Form.validate(self)
        if not rv:
            return False
        return True

# Initialize flask-login
def init_login():
    login_manager = login.LoginManager()
    login_manager.anonymous_user = Anonymous
    login_manager.init_app(app)

    # Create user loader function
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.query(User).get(user_id)

#todo
class UserProfileView(BaseView):
    fakePassword = "******"

    def is_accessible(self):
        return login.current_user.is_authenticated

    @expose('/', methods=['GET'])
    def index(self):    
        try:
            changeEmailForm = ChangeEmailForm()
            changeEmailForm.email.data = login.current_user.email
            changePasswordForm = ChangePasswordForm()
            response = self.render('user_profile_page.html',changeEmailForm=changeEmailForm, changePasswordForm=changePasswordForm)
        except Exception, err:
            logger.error(traceback.format_exc())
        return response

    @expose('/changeemail', methods=['POST'])
    def changeEmail(self):
        try:
            changeEmailForm = ChangeEmailForm(request.form)
            if helpers.validate_form_on_submit(changeEmailForm):
                login.current_user.email = changeEmailForm.email.data
                db.session.commit()
                logger.warning("UserID = %d, email changed to %s" % (login.current_user.id, login.current_user.email))
                flash(u'Email is modified successfully！')

            changePasswordForm = ChangePasswordForm()
            response = self.render('user_profile_page.html',changeEmailForm=changeEmailForm, changePasswordForm=changePasswordForm)
        except Exception,err:
            logger.error(traceback.format_exc())
        return response

    @expose('/changepassword', methods=['POST'])
    def changePassword(self):
        try:
            changePasswordForm = ChangePasswordForm(request.form)
            if helpers.validate_form_on_submit(changePasswordForm):
                login.current_user.password = generate_password_hash(changePasswordForm.password.data)
                db.session.commit()
                logger.warning("UserID = %s, password changed" % login.current_user.id)
                flash(u'Password is changed successfully！')
            changeEmailForm = ChangeEmailForm()
            changeEmailForm.email.data = login.current_user.email
            response = response = self.render('user_profile_page.html',changeEmailForm=changeEmailForm, changePasswordForm=changePasswordForm)
        except Exception,err:
            logger.error(traceback.format_exc())
        return response

class UserView(sqla.ModelView):
    can_edit = False
    column_exclude_list = ["password"]
    #inline edit
    column_editable_list = ["name","email","isAdmin"]
    column_searchable_list = (User.name, User.email)
    column_labels = dict(name="Name",email="Email",isAdmin="isAdmain?")
    def is_accessible(self):
        return login.current_user.is_admin()
    def on_model_change(self, form, model, is_created=False):
        # used for create user
        if is_created:
            model.password = generate_password_hash(form.password.data)
        logger.warning("UserID = %d, admin user view. Model[id=%s] changed to: created?[%s], name[%s], isAdmin[%s], email[%s]." %(login.current_user.id, model.id, is_created, model.name,model.isAdmin,model.email))
    
    def on_model_delete(self, model):
        logger.warning("UserID = %d, admin user view. Model[id=%d] deleted: name[%s], isAdmin[%s], email[%s]." %(login.current_user.id, model.id, model.name,model.isAdmin,model.email))

class HelpView(BaseView):
    @expose('/')
    def index(self):
        return self.render('help.html')

class TreeView(sqla.ModelView):
    column_exclude_list = ['children']
    column_searchable_list = [TreeNode.name]
    column_labels = dict(name="Team name",parent="Team Manager name", children="Team member name(s)")
    def is_accessible(self):
        return login.current_user.is_admin()
    def on_model_change(self, form, model, is_created):
        logger.warning("UserID = %d, admin tree view. Model[id=%s] changed to: created?[%s], name[%s], children%s, parent[%s]." %(login.current_user.id, model.id, is_created, model.name,model.children,model.parent))

    def on_model_delete(self, model):
        logger.warning("UserID = %d, admin tree view. Model[id=%d] deleted: name[%s], children%s, parent[%s]." %(login.current_user.id, model.id,model.name,model.children,model.parent))

class CalendarView(BaseView):
    def is_accessible(self):
        return login.current_user.is_authenticated

    @expose('/')
    def index(self):
        return self.render('calendar/view.html')

# Create customized index view class that handles login & registration, with view MyAdminIndexView
class MyAdminIndexView(admin.AdminIndexView):

    @expose('/')
    def index(self):
        if not login.current_user.is_authenticated:
            return redirect(url_for('index'))
        try:
            response = make_response(super(MyAdminIndexView, self).index())
            logger.info(response)
        except Exception, err:
            logger.error(traceback.format_exc())
        # response.set_cookie('focusedUserName', login.current_user.name)
        response.set_cookie('currentUserName', login.current_user.name)
        return response

    @expose('/logout/')
    def logout_view(self):
        userID = login.current_user.id
        login.logout_user()
        logger.warning("UserID = %d, logout." % userID)
        return redirect(url_for('index'))

# Flask views
@app.route('/', methods=('GET', 'POST'))
def index():
    if request.method == 'GET':
        form = LoginForm();
        return render_template('login.html',form=form)
    else:
        form = LoginForm(request.form)
        validate = helpers.validate_form_on_submit(form)
        if validate:
            login.login_user(form.user)

        if login.current_user.is_authenticated:
            logger.warning("UserID = %d, login successfully, email = %s" %(login.current_user.id, form.email.data))
            return redirect(url_for('admin.index'))
        logger.warning("Login failed, email: " + form.email.data)
        return render_template('login.html', form=form) 

def getFocusedUserFromCookies(cookies):
    focusedUserName = cookies.get('focusedUserName')
    focusedUser = None;
    if focusedUserName is not None:
        focusedUser = db.session.query(User).filter_by(name=focusedUserName).first()
    if focusedUser is None:
        focusedUser = login.current_user
    return focusedUser

@app.route('/getevents')
@login_required
def getEvents(): 
    userID = login.current_user.id
    try:
        focusedUser = getFocusedUserFromCookies(request.cookies) #todo authentification
        startDate = request.args['start']
        endDate = request.args['end']
        events = db.session.query(Event).filter(
                Event.userID==focusedUser.id, Event.date>=startDate, Event.date<=endDate
            ).all()
        
        objects_list =[]
        for event in events:
            d = collections.OrderedDict()
            d['id'] = event.id
            d['start'] = str(event.date)
            d['title'] = event.content
            objects_list.append(d)
        js = json.dumps(objects_list)
        resp = Response(js, status=200, mimetype='application/json')
        resp.set_cookie('focusedUserName', focusedUser.name)
        resp.set_cookie('currentUserName', login.current_user.name)
        logger.warning("userID = %d, get events[%s ~ %s], focused user id= %s" %(userID, startDate, endDate, focusedUser.id))
    except Exception, err:
        logger.error(traceback.format_exc())
    return resp

@app.route('/getusertree')
@login_required
def getUserTree():
    userName = login.current_user.name
    node = db.session.query(User).\
                    options(joinedload_all("children", "children",
                                            "children", "children")).\
                    filter(User.name == userName).\
                    first()
    responseList = []
    responseList.append(node.dump())
    js = json.dumps(responseList)
    return Response(js, status=200, mimetype='application/json')

@app.route('/createevent',methods=['POST'])
@login_required
def createEvent():
    userID = login.current_user.id
    focusedUser = getFocusedUserFromCookies(request.cookies)
    if focusedUser.id != userID:
        return "Not permited."

    date = request.form.get('date');
    content = request.form.get('content')
    event = Event()
    event.userID = userID
    event.date = date
    event.content = content
    db.session.add(event)
    db.session.commit()
    logger.warning("userID = %d, create event, event date = %s" %(userID, date))
    return "Good!"#todo

@app.route('/deleteevent',methods=['POST'])
@login_required
def deleteEvent():
    userID = login.current_user.id
    focusedUser = getFocusedUserFromCookies(request.cookies)
    if focusedUser.id != userID:
        return "Not permited."

    eventId = request.form.get('id');
    db.session.query(Event).filter(Event.id == eventId).delete()
    db.session.commit()
    logger.warning("UserID = %d, delete event, eventID = %s" % (userID, eventId))
    return "Good!"

@app.route('/updateevent',methods=['POST'])
@login_required
def updateEvent():
    userID = login.current_user.id
    focusedUser = getFocusedUserFromCookies(request.cookies)
    if focusedUser.id != userID:
        return "Not permited."#todo

    eventId = request.form.get('id');
    content = request.form.get('content');
    event = Event.query.filter_by(id=eventId).first()
    event.content = content
    db.session.commit()
    logger.warning("UserID = %d, update event, eventID = %s" % (userID, eventId))
    return "Good!"

# Initialize flask-login
init_login()

# Create admin, with view MyAdminIndexView
admin = admin.Admin(app, 'Week report system', index_view=MyAdminIndexView(name='Home'), base_template='my_master.html')

# Add view
admin.add_view(UserProfileView(name='Profile'))
admin.add_view(UserView(User, db.session, name='User Management'))
admin.add_view(TreeView(TreeNode, db.session, name='Organization'))
admin.add_view(HelpView(name='Help'))

app.debug = True
app.run(host='0.0.0.0', port=80)
