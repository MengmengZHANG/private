#!/usr/bin/env python
# -*- coding: utf-8 -*-
from wtforms import form, StringField, PasswordField
from wtforms.validators import Required, Email
from database import db, User
from werkzeug.security import check_password_hash

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