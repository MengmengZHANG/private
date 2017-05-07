#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os,sys
root = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(root, 'site-packages'))

#flask
from flask import Flask, flash, url_for, redirect, render_template, request,Response,session,g, make_response
from flask.views import View
import flask_admin as admin
from flask_admin import helpers, expose
import flask_login as login
from flask.ext.login import login_required, AnonymousUserMixin
from flask.ext.admin import BaseView

#password
from werkzeug.security import generate_password_hash, check_password_hash

#db
from flask_sqlalchemy import SQLAlchemy
from flask.ext.admin.contrib import sqla
from sqlalchemy.orm import joinedload_all
from sqlalchemy.orm.collections import attribute_mapped_collection

#form
from wtforms import form, fields, StringField, PasswordField, SubmitField, validators
from wtforms.validators import Required, Email

#localization
from flask.ext.babelex import Babel

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

# Initialize babel
babel = Babel(app)

@babel.localeselector
def get_locale():
    return "zh"

#local
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin@localhost/app_weekreport'
db = SQLAlchemy(app)

# sae
# from sae.const import (MYSQL_HOST, MYSQL_HOST_S,
#     MYSQL_PORT, MYSQL_USER, MYSQL_PASS, MYSQL_DB)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://%s:%s@%s:%s/%s' % (MYSQL_USER,MYSQL_PASS,MYSQL_HOST,MYSQL_PORT,MYSQL_DB)

#To reconnect db when time out of sae (30s)
# class nullpool_SQLAlchemy(SQLAlchemy):
#     def apply_driver_hacks(self, app, info, options):
#         super(nullpool_SQLAlchemy, self).apply_driver_hacks(app, info, options)
#         from sqlalchemy.pool import NullPool
#         options['poolclass'] = NullPool
#         del options['pool_size']
# db = nullpool_SQLAlchemy(app)
#
# @app.before_request
# def before_request():
#    db = nullpool_SQLAlchemy(app)
#
# @app.teardown_request
# def teardown_request(exception):
#     db.session.close()

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
    name = db.Column(db.String(100))
    isAdmin = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(120), nullable = False)
    password = db.Column(db.String(160), nullable = False)
    def is_authenticated(self):
        return True
    def is_admin(self):
        return self.isAdmin
    def is_active(self):
        return True
    def is_anonymous(self):
        return False
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

# admin = User()
# admin.name = 'admin'
# admin.email = 'admin@test.com'
# admin.isAdmin = True
# admin.password = generate_password_hash('admin2017')
#
# guest = User()
# guest.name = 'guest'
# guest.email = 'guest@test.com'
# guest.isAdmin = False
# guest.password = generate_password_hash('guest2017')
#
# db.session.add(admin)
# db.session.add(guest)
# db.session.commit()
# db.create_all()
# db.session.commit()

# Define login and registration forms (for flask-login)
class LoginForm(form.Form):
    email = StringField(u'邮箱', [Required(message=u'*必填项'), Email(message=u'无效的邮箱地址')])#todo css
    password = PasswordField(u'密码', [Required(message=u'*必填项')])

    def validate(self):
        rv = form.Form.validate(self)
        if not rv:
            return False

        user = db.session.query(User).filter_by(email=self.email.data).first()

        if user is None:
            self.email.errors.append(u'无此用户')
            return False

        # we're comparing the plaintext pw with the the hash from the db
        if not check_password_hash(user.password, self.password.data):
        # to compare plain text passwords use
        # if user.password != self.password.data:
            self.password.errors.append(u'密码错误')
            return False
        self.user = user
        return True

class ChangeEmailForm(form.Form):
    email = StringField('email', [Required(message=u'请输入您的新邮箱地址'), Email(message=u'无效的邮箱地址')])#todo css
    def validate(self):
        rv = form.Form.validate(self)
        if not rv:
            return False
        return True

class ChangePasswordForm(form.Form):
    password = PasswordField(u'密码', [Required(message=u'请输入您的新密码')])
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
        return login.current_user.is_authenticated()

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
                flash(u'邮箱已修改！')

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
                flash(u'密码已修改！')
            changeEmailForm = ChangeEmailForm()
            changeEmailForm.email.data = login.current_user.email
            response = response = self.render('user_profile_page.html',changeEmailForm=changeEmailForm, changePasswordForm=changePasswordForm)
        except Exception,err:
            logger.error(traceback.format_exc())
        return response

class UserView(sqla.ModelView):
    column_exclude_list = ["password"]
    column_searchable_list = (User.name, User.email)
    column_labels = dict(name=u"姓名",email=u"邮箱",isAdmin=u"管理员",password=u"密码")
    def is_accessible(self):
        return login.current_user.is_admin()
    def on_model_change(self, form, model, is_created=False):
        model.password = generate_password_hash(form.password.data)
        logger.warning("UserID = %d, admin user view. Model[id=%s] changed to: created?[%s], name[%s], isAdmin[%s], email[%s]." %(login.current_user.id, model.id, is_created, model.name,model.isAdmin,model.email))
    
    def on_model_delete(self, model):
        logger.warning("UserID = %d, admin user view. Model[id=%d] deleted: name[%s], isAdmin[%s], email[%s]." %(login.current_user.id, model.id, model.name,model.isAdmin,model.email))

class TreeView(sqla.ModelView):
    column_exclude_list = ['children']
    column_searchable_list = [TreeNode.name]
    column_labels = dict(name=u"本节点名称",parent=u"上级名称", children=u"下级名称")
    def is_accessible(self):
        return login.current_user.is_admin()
    def on_model_change(self, form, model, is_created):
        logger.warning("UserID = %d, admin tree view. Model[id=%s] changed to: created?[%s], name[%s], children%s, parent[%s]." %(login.current_user.id, model.id, is_created, model.name,model.children,model.parent))
    
    def on_model_delete(self, model):
        logger.warning("UserID = %d, admin tree view. Model[id=%d] deleted: name[%s], children%s, parent[%s]." %(login.current_user.id, model.id,model.name,model.children,model.parent))

class CalendarView(BaseView):
    def is_accessible(self):
        return login.current_user.is_authenticated()

    @expose('/')
    def index(self):
        return self.render('calendar/view.html')

# Create customized index view class that handles login & registration, with view MyAdminIndexView
class MyAdminIndexView(admin.AdminIndexView):

    @expose('/')
    def index(self):
        if not login.current_user.is_authenticated():
            return redirect(url_for('index'))
        try:
            response = make_response(super(MyAdminIndexView, self).index())
        except Exception, err:
            logger.error(traceback.format_exc())
        response.set_cookie('focusedUserName', login.current_user.name)
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

        if login.current_user.is_authenticated():
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
    node = db.session.query(TreeNode).\
                    options(joinedload_all("children", "children",
                                            "children", "children")).\
                    filter(TreeNode.name == userName).\
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
admin = admin.Admin(app, u'工作日志系统', index_view=MyAdminIndexView(name=u'首页'), base_template='my_master.html')

# Add view
admin.add_view(UserProfileView(name=u'个人信息'))
admin.add_view(UserView(User, db.session, name=u'用户管理'))
admin.add_view(TreeView(TreeNode, db.session, name=u'组织结构'))

app.debug = True
app.run(port=8080)
