#!/usr/bin/env python
# -*- coding: utf-8 -*-


from flask import url_for, redirect, make_response
import flask_login as login
from flask_admin import expose
import flask_admin
import logging
import traceback

# Create customized index view class that handles login & registration, with view MyAdminIndexView
class MyAdminIndexView(flask_admin.AdminIndexView):
    @expose('/')
    def index(self):
        if not login.current_user.is_authenticated:
            return redirect(url_for('index'))
        try:
            response = make_response(super(MyAdminIndexView, self).index())
            logging.getLogger('Functional').info(response)
        except Exception, err:
            logging.getLogger('Functional').error(traceback.format_exc())
        # response.set_cookie('focusedUserName', login.current_user.name)
        response.set_cookie('currentUserName', login.current_user.name)
        return response

    @expose('/logout/')
    def logout_view(self):
        userID = login.current_user.id
        login.logout_user()
        logging.getLogger('Functional').warning("UserID = %d, logout." % userID)
        return redirect(url_for('index'))
