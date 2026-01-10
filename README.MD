Exclude multiple DB-related files (recommended)

zip -r ../flask_app.zip . -x "*.db" "__pycache__/*" "venv/*"


Verify what’s inside the zip:

unzip -l flask_app.zip


