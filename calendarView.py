#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask_admin import BaseView, expose
import flask_login as login

class CalendarView(BaseView):
    def is_accessible(self):
        return login.current_user.is_authenticated

    @expose('/')
    def index(self):
        return self.render('calendar/view.html')