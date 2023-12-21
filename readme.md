# Flask File Sharing API

Welcome to the Flask File Sharing API! This project provides a Flask-based backend for file management, user authentication, and email verification.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Endpoints](#endpoints)

## Introduction

The Flask File Sharing API is designed to handle user registration, authentication, and file upload/download operations. It incorporates features like email verification and uses Flask extensions for enhanced functionality.

## Features

- User registration and login
- Email verification for user accounts
- Secure file upload and download
- Create jwt token for verification
- Uses sqlite3 for the database

## Getting Started

- clone the repo
- run the command `python index3.py`
- make sure you have create a mail server(i used mailtrap for that)
- install all the dependencies

### Prerequisites

Make sure you have the following installed before running the project:

- Python (version x.x)
- flask
- werkzeug
- datetime
- jwt
- os
- flask_bcrypt
- flask_mail
- flask_sqlalchemy
- flask_jwt_extended

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/your-repo.git
   ```

2. Install all the dependencies
3. Create a user account on mailtrap.io or somthing similar
4. setup the db (sqlite3 prefferd)

### Endpoints

1. Home Page:  
   Endpoint: /  
   Method: GET  
   Description: Displays a welcome message.

2. User Registration:  
   Endpoint: /signup  
   Method: POST  
   Description: Registers a new user.  
   Request Body: JSON with email, password, and userType.  

3. User Login:  
   Endpoint: /login  
   Method: POST  
   Description: Logs in a user.  
   Request Body: JSON with email and password.

4. File Upload:  
   Endpoint: /upload  
   Method: POST  
   Description: Uploads a file.  
   Authentication: Requires a valid JWT token.  
   Request Body: Form data with a file attached.

5. File Download:  
   Endpoint: /download/<int:file_id>  
   Method: GET  
   Description: Downloads a file.  
   Authentication: Requires a valid JWT token.  
   URL Parameter: file_id (integer) - the ID of the file to download.

6. Email Verification:  
   Endpoint: /verify-email/<string:token>  
   Method: GET  
   Description: Verifies the user's email based on the provided token.  
   URL Parameter: token (string) - the verification token.
