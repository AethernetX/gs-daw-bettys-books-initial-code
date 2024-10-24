# Create database script for Bettys books

# Create the database
CREATE DATABASE IF NOT EXISTS bettys_books;
USE bettys_books;

# Create the tables
CREATE TABLE IF NOT EXISTS books (id INT AUTO_INCREMENT primary key NOT NULL,name VARCHAR(50),price DECIMAL(5, 2) unsigned,PRIMARY KEY(id), publication DATE, stock TINYINT unsigned);

CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT primary key NOT NULL,firstName VARCHAR(23), lastName VARCHAR(23), email VARCHAR(40), username VARCHAR(23), isAdmin BOOL DEFAULT FALSE, password VARCHAR(70));

# Create the app user
CREATE USER IF NOT EXISTS 'bettys_books_app'@'localhost' IDENTIFIED BY 'qwertyuiop'; 
GRANT ALL PRIVILEGES ON bettys_books.* TO ' bettys_books_app'@'localhost';
