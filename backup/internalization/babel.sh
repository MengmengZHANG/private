#!/bin/sh
pybabel extract -F babel.ini -k _gettext -k _ngettext -k lazy_gettext -o admin.pot --project Flask-Admin ../flask_admin
pybabel compile -D admin -d ../flask_admin/translations/
pybabel init -D admin -i admin.pot -d ../flask_admin/translations/ -l zh_CN
pybabel compile -D admin -d translations/
