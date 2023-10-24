CREATE TABLE user (
    user_id INT AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    password_hash VARCHAR(60) NOT NULL,
    password_salt CHAR(16) NOT NULL,

    first_name VARCHAR(100),
    last_name VARCHAR(100),
    email VARCHAR(255) NOT NULL,

    UNIQUE (username),
    UNIQUE (email),

    balance INT,
    PRIMARY KEY (user_id)
);