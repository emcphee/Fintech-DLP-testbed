import json
import psycopg2

db_params = {
    "database": "db",
    "user": "postgres",
    "password": "admin",
    "host": "127.0.0.1",
    "port": "5432",
}

connection = psycopg2.connect(**db_params)
cursor = connection.cursor()

DATA_FILE = "fake_records.json"
USER_PASS_FILE = "users_and_passwords.csv"

with open(DATA_FILE, 'r') as infile:
    data = infile.read()
    entries = json.loads(data)

with open(USER_PASS_FILE, 'w') as outfile:
    for entry in entries:
        username,fname,lname,email,password,password_salt,password_hash = entry.values()
        outfile.write(username + ',' + password + '\n')

        try:
            sql = "INSERT INTO users (username,first_name,last_name,email,password_hash,password_salt) \
                VALUES (%s, %s, %s, %s, %s, %s)"
            cursor.execute(sql, (username, fname, lname, email, password_hash.encode(), password_salt.encode()))
            connection.commit()
        except Exception as e:
            connection.rollback()
            print(f"Error: {e}")


cursor.close()
connection.close()