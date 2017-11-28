#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import flask_login as login
from werkzeug.security import generate_password_hash
from flask_admin.contrib import sqla
from database import User

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
        logging.getLogger('Functional').warning("UserID = %d, admin user view. Model[id=%s] changed to: created?[%s], name[%s], isAdmin[%s], email[%s]." %(login.current_user.id, model.id, is_created, model.name,model.isAdmin,model.email))

    def on_model_delete(self, model):
        logging.getLogger('Functional').warning("UserID = %d, admin user view. Model[id=%d] deleted: name[%s], isAdmin[%s], email[%s]." %(login.current_user.id, model.id, model.name,model.isAdmin,model.email))

# class TreeView(sqla.ModelView):
#     can_edit = False
#     #inline edit
#     column_editable_list = ["name","parent"]
#     column_exclude_list = ['children']
#     column_searchable_list = [TreeNode.name]
#     column_labels = dict(name="User name",parent="User's Manager's name", children="User's team member's name")
#     def is_accessible(self):
#         return login.current_user.is_admin()
#     def on_model_change(self, form, model, is_created):
#         logger.warning("UserID = %d, admin tree view. Model[id=%s] changed to: created?[%s], name[%s], children%s, parent[%s]." %(login.current_user.id, model.id, is_created, model.name,model.children,model.parent))
#
#     def on_model_delete(self, model):
#         logger.warning("UserID = %d, admin tree view. Model[id=%d] deleted: name[%s], children%s, parent[%s]." %(login.current_user.id, model.id,model.name,model.children,model.parent))
