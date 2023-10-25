CREATE TABLE users (
    user_id SERIAL,
    username VARCHAR(50) NOT NULL,

    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,

    password_hash VARCHAR(60) NOT NULL,
    password_salt CHAR(29) NOT NULL,

    UNIQUE (username),
    UNIQUE (email),

    PRIMARY KEY (user_id)
);

CREATE TABLE financial_account (
    user_id SERIAL,
    balance double precision,

    PRIMARY KEY (user_id)
);