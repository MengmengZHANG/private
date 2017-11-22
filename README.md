This branch is used to backup the weekreport python project, that was once developped for the daily worklog system of police station of LIU Hang.

============Install=================

(1)(optional) virtualenv ENV: initialize /ENV

(2) activate script
	- linux
		- source ENV/bin/activate
		- deactivate
	- windows
		- /ENV/Scripts/activate.bat
		- /ENV/Scripts/deactivate.bat
(3) (optional) Removing an Environment
	- linux
		rm -r /path/to/ENV
(4) pip install -r requirements.txt
(5) python app.py or ./run.sh
(6)./k.sh
====================================
TODO:
update requirements.txt version


pip install --target=site-packages -r requirements.txt

cat config.yaml

saecloud deploy

dev_server.py

dev_server.py --mysql=root:admin@localhost:8080


For 500 server internal error

try:

except Exception, err:

            print traceback.format_exc()


svn command to delete all locally missing files

svn st | grep ^! | awk '{print " --force "$2}' | xargs svn rm


pybabel extract -F babel.ini -k _gettext -k _ngettext -k lazy_gettext -o admin.pot --project Flask-Admin ../flask_admin

pybabel compile -D admin -d ../flask_admin/translations/

pybabel init -D admin -i admin.pot -d ../flask_admin/translations/ -l zh_CN

pybabel compile -D admin -d translations/


Flask-Admin==1.0.9 so you should uninstall your local flask-admin

