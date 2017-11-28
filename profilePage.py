#!/usr/bin/env python
# -*- coding: utf-8 -*-
from wtforms import form, StringField, PasswordField
from wtforms.validators import Required, Email

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