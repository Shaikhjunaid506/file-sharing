
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
import datetime
import jwt
from functools import wraps
from email.mime.text import MIMEText
import smtplib
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file_sharing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pptx', 'docx', 'xlsx'}
app.config['JWT_SECRET'] = 'jwt-secret-key'
app.config['FERNET_KEY'] = Fernet.generate_key()  
app.config['EMAIL_CONFIG'] = {
    'sender': 'noreply@fileshare.com',
    'smtp_server': 'smtp.example.com',
    'smtp_port': 587,
    'username': '',
    'password': ''
}


db.init_app(app)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def send_verification_email(email, verification_url):
    msg = MIMEText(f'Please verify your email by clicking this link: {verification_url}')
    msg['Subject'] = 'Email Verification'
    msg['From'] = app.config['EMAIL_CONFIG']['sender']
    msg['To'] = email
    
    with smtplib.SMTP(app.config['EMAIL_CONFIG']['smtp_server'], 
                      app.config['EMAIL_CONFIG']['smtp_port']) as server:
        server.starttls()
        server.login(app.config['EMAIL_CONFIG']['username'],
                    app.config['EMAIL_CONFIG']['password'])
        server.send_message(msg)

def generate_jwt_token(user_id, is_ops_user=False):
    payload = {
        'user_id': user_id,
        'is_ops_user': is_ops_user,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

def ops_user_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if not current_user.is_ops_user:
            return jsonify({'message': 'Operation user required!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

def client_user_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.is_ops_user:
            return jsonify({'message': 'Client user required!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid credentials!'}), 401
    
    if not user.is_verified and not user.is_ops_user:
        return jsonify({'message': 'Email not verified!'}), 401
    
    token = generate_jwt_token(user.id, user.is_ops_user)
    return jsonify({
        'token': token,
        'is_ops_user': user.is_ops_user
    })

# Operation User APIs
@app.route('/api/ops/upload', methods=['POST'])
@token_required
@ops_user_required
def upload_file(current_user):
    if 'file' not in request.files:
        return jsonify({'message': 'No file part!'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file!'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'message': 'Invalid file type! Only pptx, docx, xlsx allowed.'}), 400
    
    filename = secure_filename(file.filename)
    file_id = str(uuid.uuid4())
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    file.save(filepath)
    
    file_type = filename.rsplit('.', 1)[1].lower()
    file_size = os.path.getsize(filepath)
    
    new_file = File(
        id=file_id,
        filename=filename,
        filepath=filepath,
        file_type=file_type,
        uploader_id=current_user.id,
        size=file_size
    )
    db.session.add(new_file)
    db.session.commit()
    
    return jsonify({
        'message': 'File uploaded successfully!',
        'file_id': file_id
    })


@app.route('/api/client/signup', methods=['POST'])
def client_signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered!'}), 400
    
    verification_token = str(uuid.uuid4())
    new_user = User(
        email=email,
        is_ops_user=False,
        verification_token=verification_token
    )
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    verification_url = f"http://example.com/verify-email?token={verification_token}"
    send_verification_email(email, verification_url)
    
    
    fernet = Fernet(app.config['FERNET_KEY'])
    encrypted_url = fernet.encrypt(verification_url.encode()).decode()
    
    return jsonify({
        'message': 'User registered! Verification email sent.',
        'encrypted_url': encrypted_url
    })

@app.route('/api/client/verify-email', methods=['POST'])
def verify_email():
    token = request.args.get('token')
    if not token:
        return jsonify({'message': 'Token is required!'}), 400
    
    user = User.query.filter_by(verification_token=token).first()
    if not user:
        return jsonify({'message': 'Invalid token!'}), 400
    
    user.is_verified = True
    user.verification_token = None
    db.session.commit()
    
    return jsonify({'message': 'Email verified successfully!'})

@app.route('/api/client/files', methods=['GET'])
@token_required
@client_user_required
def list_files(current_user):
    files = File.query.all()
    files_data = [{
        'id': file.id,
        'filename': file.filename,
        'file_type': file.file_type,
        'uploaded_at': file.uploaded_at.isoformat(),
        'size': file.size
    } for file in files]
    
    return jsonify(files_data)

@app.route('/api/client/files/<file_id>/download', methods=['GET'])
@token_required
@client_user_required
def generate_download_url(current_user, file_id):
    file = File.query.get(file_id)
    if not file:
        return jsonify({'message': 'File not found!'}), 404
    
   
    download_token = str(uuid.uuid4())
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    
    new_token = DownloadToken(
        token=download_token,
        file_id=file_id,
        user_id=current_user.id,
        expires_at=expires_at
    )
    db.session.add(new_token)
    db.session.commit()
    
   
    download_url = f"http://example.com/api/client/download/{download_token}"
    
    
    fernet = Fernet(app.config['FERNET_KEY'])
    encrypted_url = fernet.encrypt(download_url.encode()).decode()
    
    return jsonify({
        'download_url': encrypted_url,
        'expires_at': expires_at.isoformat()
    })

@app.route('/api/client/download/<token>', methods=['GET'])
def download_file(token):
    download_token = DownloadToken.query.filter_by(token=token).first()
    if not download_token:
        return jsonify({'message': 'Invalid download token!'}), 404
    
    if download_token.expires_at < datetime.datetime.utcnow():
        return jsonify({'message': 'Download token expired!'}), 410
    
    if download_token.is_used:
        return jsonify({'message': 'Download token already used!'}), 410
    
    file = File.query.get(download_token.file_id)
    if not file:
        return jsonify({'message': 'File not found!'}), 404
    
    
    download_token.is_used = True
    db.session.commit()
    
    return send_from_directory(
        directory=os.path.dirname(file.filepath),
        path=os.path.basename(file.filepath),
        as_attachment=True,
        download_name=file.filename
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)