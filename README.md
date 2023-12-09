# Fintech-DLP-testbed

## Deployed at: https://big-bank.me/

# Steps on running the website locally
- Step 1: Ensure Python is installed, and run pip install on the requirements.txt
- Step 2: Install Postgres and create an empty database with matching credentials as they are in the Django settings.py file
- Step 3: Run: Python fintech_testbed_project/manage.py makemigrations, and then Python fintech_testbed_project/manage.py migrate
- Step 4: Run: Python fintech_testbed_project/manage.py runserver
- Step 4: Connect to localhost:8000 through a web browser

## Notes:
- DB dump not included, as the site can be run with full functionality without a filled DB
- DB Schema is listed in the Django models.py file
