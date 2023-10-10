FROM python:latest

WORKDIR /home

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["python", "./fintech_testbed_project/manage.py", "runserver", "0.0.0.0:8000"]
