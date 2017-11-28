#!/usr/bin/env python
# -*- coding: utf-8 -*-
import config

from flask import Flask, flash, url_for, redirect, render_template, request,Response, make_response
import flask_admin as admin
from flask_admin import helpers, expose
import flask_login as login
from flask_login.utils import login_required
from flask_login.mixins import AnonymousUserMixin

#db
from database import db, User, Event, initDatabase

#pages & views
from loginPage import LoginForm
from myAdminIndexView import MyAdminIndexView
from profileView import UserProfileView
from helpView import HelpView
from userManagementView import UserView

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
db.init_app(app)
#initDatabase()

# Guest user
class Anonymous(AnonymousUserMixin):
    def is_admin(self):
        return False
    def has_children(self):
        return False

# Initialize flask-login
def init_login():
    login_manager = login.LoginManager()
    login_manager.anonymous_user = Anonymous
    login_manager.init_app(app)

    # Create user loader function
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.query(User).get(user_id)

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

# @app.route('/getusertree')
# @login_required
# def getUserTree():
#     userName = login.current_user.name
#     node = db.session.query(User).\
#                     options(joinedload_all("children", "children",
#                                             "children", "children")).\
#                     filter(User.name == userName).\
#                     first()
#     responseList = []
#     responseList.append(node.dump())
#     js = json.dumps(responseList)
#     return Response(js, status=200, mimetype='application/json')

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
# admin.add_view(TreeView(TreeNode, db.session, name='Organization'))
admin.add_view(HelpView(name='Help'))

app.debug = True
app.run(host='0.0.0.0', port=8080)
