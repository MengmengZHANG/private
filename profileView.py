#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask_admin import BaseView, helpers, expose
from flask import flash, request
from profilePage import ChangeEmailForm, ChangePasswordForm
import logging
import flask_login as login
from database import db
from werkzeug.security import generate_password_hash
import traceback

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
            logging.getLogger('Functional').error(traceback.format_exc())
        return response

    @expose('/changeemail', methods=['POST'])
    def changeEmail(self):
        try:
            changeEmailForm = ChangeEmailForm(request.form)
            if helpers.validate_form_on_submit(changeEmailForm):
                login.current_user.email = changeEmailForm.email.data
                db.session.commit()
                logging.getLogger('Functional').warning("UserID = %d, email changed to %s" % (login.current_user.id, login.current_user.email))
                flash(u'Email is modified successfully！')

            changePasswordForm = ChangePasswordForm()
            response = self.render('user_profile_page.html',changeEmailForm=changeEmailForm, changePasswordForm=changePasswordForm)
        except Exception,err:
            logging.getLogger('Functional').error(traceback.format_exc())
        return response

    @expose('/changepassword', methods=['POST'])
    def changePassword(self):
        try:
            changePasswordForm = ChangePasswordForm(request.form)
            if helpers.validate_form_on_submit(changePasswordForm):
                login.current_user.password = generate_password_hash(changePasswordForm.password.data)
                db.session.commit()
                logging.getLogger('Functional').warning("UserID = %s, password changed" % login.current_user.id)
                flash(u'Password is changed successfully！')
            changeEmailForm = ChangeEmailForm()
            changeEmailForm.email.data = login.current_user.email
            response = response = self.render('user_profile_page.html',changeEmailForm=changeEmailForm, changePasswordForm=changePasswordForm)
        except Exception,err:
            logging.getLogger('Functional').error(traceback.format_exc())
        return response