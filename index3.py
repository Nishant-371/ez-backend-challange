from flask import Flask, jsonify, request, redirect, url_for
from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_limiter.util import get_remote_address
import os
import jwt
import datetime
from werkzeug.utils import secure_filename


app = Flask(__name__)
api = Api(app)

# Configure Flask JWT Extended
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
jwt = JWTManager(app)

# Configure Flask Mail
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = '***********'
app.config['MAIL_PASSWORD'] = '***********'
mail = Mail(app)

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'  # SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    userType = db.Column(db.String(50), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)


    def __init__(self, email, password, userType, email_verified=False):
        self.email = email
        self.password = password
        self.userType = userType
        self.email_verified = email_verified

    def __repr__(self):
        return f"User(email='{self.email}', userType='{self.userType}', email_verified={self.email_verified})"

# Define File Model
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filetype = db.Column(db.String(50), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_type = db.Column(db.String(50), nullable=False)
    
    user = db.relationship('User', backref=db.backref('files', lazy=True))

    def __repr__(self):
        return f"File(id={self.id}, filename='{self.filename}', filetype='{self.filetype}', filepath='{self.filepath}', user_id={self.user_id}, user_type='{self.user_type}')"





# Configure Flask Bcrypt
bcrypt = Bcrypt(app)

# Configure file upload folder
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}







# Resource parsers
user_signup_parser = reqparse.RequestParser()
user_signup_parser.add_argument('email', type=str, required=True)
user_signup_parser.add_argument('password', type=str, required=True)
user_signup_parser.add_argument('userType', type=str, required=True)

user_login_parser = reqparse.RequestParser()
user_login_parser.add_argument('email', type=str, required=True)
user_login_parser.add_argument('password', type=str, required=True)
user_signup_parser.add_argument('userType', type=str, required=True)

file_upload_parser = reqparse.RequestParser()
file_upload_parser.add_argument('file', type=str, location='files', required=True)


# Helper function to generate a JWT token
def generate_token(user_id):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {'user_id': user_id, 'exp': expiration_time}
    token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return token.decode('utf-8')

@app.route('/')
def homepage():
    return jsonify({'message': 'Welcome to the File Sharing API'})



 # Resources
class UserSignupResource(Resource):
    def post(self):
        data=request.get_json(force=True)

        args = user_signup_parser.parse_args()

        existing_user = User.query.filter_by(email=args['email']).first()
        if existing_user:
            return {'error': 'User already exists'}, 400

        hashed_password = bcrypt.generate_password_hash(args['password']).decode('utf-8')
        new_user = User(email=args['email'], password=hashed_password, userType=args['userType'], email_verified=False)

        db.session.add(new_user)
        db.session.commit()

        send_verification_email(new_user.id, new_user.email)

        return {'message': 'User registered successfully. Check your email for verification.'}, 201

class UserLoginResource(Resource):
    def post(self):
        args = user_login_parser.parse_args()
        user = User.query.filter_by(email=args['email']).first()

        if user and bcrypt.check_password_hash(user.password, args['password']):
            if user.email_verified:     
                access_token = create_access_token(identity=user.id)
                return {'access_token': access_token}, 200
            else:
                return {'error': 'Email not verified'}, 401
        else:
            return {'error': 'Invalid credentials'}, 401

class FileUploadResource(Resource):
    @jwt_required()
    def post(self):
        args = file_upload_parser.parse_args()
        uploaded_file = args['file']

        if args['user_type']!= "operation user":
            return {'error':'Not authorize to upload file'},400

        if 'file' not in request.files or not uploaded_file:
            return {'error': 'No file provided'}, 400

        if uploaded_file.filename == '':
            return {'error': 'No selected file'}, 400

        if uploaded_file and allowed_file(uploaded_file.filename):
            filename = secure_filename(uploaded_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(file_path)

            new_file = File(filename=filename, file_type=filename.split('.')[-1], file_path=file_path, user_id=get_jwt_identity())
            db.session.add(new_file)
            db.session.commit()

            return {'file_id': new_file.id}, 201
        else:
            return {'error': 'Invalid file type'}, 400

class FileDownloadResource(Resource):
    @jwt_required()
    def get(self, file_id):
        file_to_download = File.query.get(file_id)

        if file_to_download and file_to_download.user_id == get_jwt_identity():
            # Implement secure file download logic here
            return {'message': 'File download endpoint'}, 200
        else:
            return {'error': 'File not found or unauthorized'}, 404

class EmailVerificationResource(Resource):
    def get(self, token):
        try:
            user_id = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])['identity']
            user = User.query.get(user_id)

            if user:
                user.email_verified = True
                db.session.commit()
                return redirect(url_for('verification_success'))
            else:
                return {'error': 'Invalid token'}, 400
        except jwt.ExpiredSignatureError:
            return {'error': 'Verification link has expired'}, 400
        except jwt.InvalidTokenError:
            return {'error': 'Invalid token'}, 400

# Add resources to the API
api.add_resource(UserSignupResource, '/signup')
api.add_resource(UserLoginResource, '/login')
api.add_resource(FileUploadResource, '/upload')
api.add_resource(FileDownloadResource, '/download/<int:file_id>')
api.add_resource(EmailVerificationResource, '/verify-email/<string:token>')

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def send_verification_email(user_id, email):
    verification_token = create_access_token(identity=user_id, expires_delta=datetime.timedelta(days=1))
    verification_url = f'https://yourdomain.com/verify-email/{verification_token}'

    msg = Message('Email Verification', sender='taliwalnishant@gmail.com', recipients=[email])
    msg.body = f'Click the following link to verify your email: {verification_url}'
    mail.send(msg)

# Run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
