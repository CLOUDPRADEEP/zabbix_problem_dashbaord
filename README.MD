Hello everyone, this is a side project designed to capture available problems in Zabbix using an API call and store them locally. It features an attractive dashboard where you can view analytics such as top hosts by alerts, common alert types, 30-day trends, and more.


How to Zip it : 
Exclude multiple DB-related files (recommended)

zip -r ../flask_app.zip . -x "*.db" "__pycache__/*" "venv/*"


Verify what’s inside the zip:

unzip -l flask_app.zip


