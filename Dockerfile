FROM python:latest

ENV DJANGO_SUPERUSER_USERNAME=admin
ENV DJANGO_SUPERUSER_EMAIL=admin@example.com
ENV DJANGO_SUPERUSER_PASSWORD=password

WORKDIR /home

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python ./fintech_testbed_project/manage.py makemigrations
RUN python ./fintech_testbed_project/manage.py migrate

RUN python ./fintech_testbed_project/manage.py createsuperuser --noinput

EXPOSE 8000
CMD ["python", "./fintech_testbed_project/manage.py", "runserver", "0.0.0.0:8000"]
