#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask_admin import BaseView, expose

class HelpView(BaseView):
    @expose('/')
    def index(self):
        return self.render('help.html')