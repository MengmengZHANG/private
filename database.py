#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

db = SQLAlchemy()

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
        return False
    # def has_children(self):
    #     node = db.session.query(TreeNode).\
    #                 options(joinedload_all("children", "children",
    #                                         "children", "children")).\
    #                 filter(TreeNode.name == self.name).\
    #                 first()
    #     if node:
    #         if len(node.children) >= 1:
    #             return True
    #     else:
    #         return False
    def __unicode__(self):
        return self.username

# Create user model.
class Event(db.Model):
    extend_existing=True
    id = db.Column(db.Integer, primary_key=True)
    userID = db.Column(db.Integer)
    date = db.Column(db.Date)
    content = db.Column(db.TEXT)

# class TreeNode(db.Model):
#     __tablename__ = 'tree'
#     id = db.Column(db.Integer, primary_key=True)
#     parent_id = db.Column(db.Integer, db.ForeignKey(id))
#     name = db.Column(db.String(100), nullable=False)
#
#     children = db.relationship("TreeNode",
#
#                         # many to one + adjacency list - remote_side
#                         # is required to reference the 'remote'
#                         # column in the join condition.
#                         backref=db.backref("parent", remote_side=id),
#                     )
#
#     def __repr__(self):
#         #This value also shows in UI tree node
#         return self.name;
#
#
#     def dump(self):
#         d = collections.OrderedDict()
#         d['id'] = str(self.id)
#         d['label'] = self.name
#
#         subList = []
#         for child in self.children:
#             subList.append(child.dump())
#         if subList != []:
#             d['children'] = subList
#         return d

def initDatabase():
    manager = User()
    manager.name = 'manager'
    manager.email = 'manager@test.com'
    manager.isAdmin = True
    manager.password = generate_password_hash('password2017')

    employee = User()
    employee.name = 'employee1'
    employee.email = 'employee1@test.com'
    employee.isAdmin = False
    employee.password = generate_password_hash('password2017')

    db.create_all()
    db.session.add(manager)
    db.session.add(employee)
    db.session.commit()
