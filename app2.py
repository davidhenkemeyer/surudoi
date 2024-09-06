from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    street_address = db.Column(db.String(120))
    city = db.Column(db.String(80))
    state = db.Column(db.String(80))
    zip_code = db.Column(db.String(20))
    phone_number = db.Column(db.String(20))
    locations = db.relationship('Location', backref='company', lazy=True)

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    address = db.Column(db.String(120))
    city = db.Column(db.String(80))
    state = db.Column(db.String(80))
    zip_code = db.Column(db.String(20))
    phone_number = db.Column(db.String(20))
    timeslots = db.relationship('Timeslot', backref='location', lazy=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Timeslot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    begin_time = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, nullable=False)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_company', methods=['POST'])
@jwt_required()
def create_company():
    current_user = get_jwt_identity()
    if current_user['role'] != 'SuperAdmin':
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    new_company = Company(
        name=data['name'],
        street_address=data['street_address'],
        city=data['city'],
        state=data['state'],
        zip_code=data['zip_code'],
        phone_number=data['phone_number']
    )
    db.session.add(new_company)
    db.session.commit()
    return jsonify({'message': 'Company created successfully'}), 201

@app.route('/create_location', methods=['POST'])
@jwt_required()
def create_location():
    current_user = get_jwt_identity()
    if current_user['role'] not in ['SuperAdmin', 'CompanyAdmin']:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    new_location = Location(
        company_id=data['company_id'],
        address=data['address'],
        city=data['city'],
        state=data['state'],
        zip_code=data['zip_code'],
        phone_number=data['phone_number']
    )
    db.session.add(new_location)
    db.session.commit()
    return jsonify({'message': 'Location created successfully'}), 201

@app.route('/set_location_hours', methods=['POST'])
@jwt_required()
def set_location_hours():
    current_user = get_jwt_identity()
    if current_user['role'] not in ['SuperAdmin', 'CompanyAdmin']:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    # Implement logic to set location hours
    return jsonify({'message': 'Location hours set successfully'}), 200

@app.route('/set_location_scheduling_type', methods=['POST'])
@jwt_required()
def set_location_scheduling_type():
    current_user = get_jwt_identity()
    if current_user['role'] not in ['SuperAdmin', 'CompanyAdmin']:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    # Implement logic to set location scheduling type
    return jsonify({'message': 'Location scheduling type set successfully'}), 200

@app.route('/create_user', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='scrypt')
    new_user = User(
        username=data['username'],
        password=hashed_password,
        company_id=data['company_id'],
        role=data['role']
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    access_token = create_access_token(identity={'username': user.username, 'role': user.role})
    return jsonify({'access_token': access_token}), 200

@app.route('/create_timeslot', methods=['POST'])
@jwt_required()
def create_timeslot():
    current_user = get_jwt_identity()
    if current_user['role'] not in ['SuperAdmin', 'CompanyAdmin']:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    new_timeslot = Timeslot(
        location_id=data['location_id'],
        begin_time=data['begin_time'],
        duration=data['duration']
    )
    db.session.add(new_timeslot)
    db.session.commit()
    return jsonify({'message': 'Timeslot created successfully'}), 201

@app.route('/join_waitlist', methods=['POST'])
@jwt_required()
def join_waitlist():
    current_user = get_jwt_identity()
    if current_user['role'] not in ['SuperAdmin', 'CompanyAdmin', 'User']:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    # Implement logic to join waitlist
    return jsonify({'message': 'Joined waitlist successfully'}), 200

@app.route('/reserve', methods=['POST'])
@jwt_required()
def reserve():
    current_user = get_jwt_identity()
    if current_user['role'] not in ['SuperAdmin', 'CompanyAdmin', 'User']:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    # Implement logic to reserve timeslot
    return jsonify({'message': 'Timeslot reserved successfully'}), 200

@app.route('/get_companies', methods=['GET'])
@jwt_required()
def get_companies():
    companies = Company.query.all()
    return jsonify([company.name for company in companies]), 200

@app.route('/get_locations/<company_id>', methods=['GET'])
@jwt_required()
def get_locations(company_id):
    locations = Location.query.filter_by(company_id=company_id).all()
    return jsonify([location.address for location in locations]), 200

@app.route('/get_users/<company_id>', methods=['GET'])
@jwt_required()
def get_users(company_id):
    users = User.query.filter_by(company_id=company_id).all()
    return jsonify([user.username for user in users]), 200

@app.route('/get_timeslots/<company_id>/<location_id>', methods=['GET'])
@jwt_required()
def get_timeslots(company_id, location_id):
    timeslots = Timeslot.query.filter_by(location_id=location_id).all()
    return jsonify([timeslot.begin_time for timeslot in timeslots]), 200

@app.route('/get_wait_time/<company_id>/<location_id>', methods=['GET'])
@jwt_required()
def get_wait_time(company_id, location_id):
    # Implement logic to get wait time
    return jsonify({'wait_time': '10 minutes'}), 200

@app.route('/delete_company/<company_id>', methods=['DELETE'])
@jwt_required()
def delete_company(company_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'SuperAdmin':
        return jsonify({'message': 'Permission denied'}), 403

    company = Company.query.get(company_id)
    db.session.delete(company)
    db.session.commit()
    return jsonify({'message': 'Company deleted successfully'}), 200

@app.route('/delete_location/<location_id>', methods=['DELETE'])
@jwt_required()
def delete_location(location_id):
    current_user = get_jwt_identity()
    if current_user['role'] not in ['SuperAdmin', 'CompanyAdmin']:
        return jsonify({'message': 'Permission denied'}), 403

    location = Location.query.get(location_id)
    db.session.delete(location)
    db.session.commit()
    return jsonify({'message': 'Location deleted successfully'}), 200

@app.route('/delete_user/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user = get_jwt_identity()
    if current_user['role'] not in ['SuperAdmin', 'CompanyAdmin']:
        return jsonify({'message': 'Permission denied'}), 403

    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'}), 200

@app.route('/delete_timeslot/<company_id>/<location_id>/<timeslot_id>', methods=['DELETE'])
@jwt_required()
def delete_timeslot(company_id, location_id, timeslot_id):
    current_user = get_jwt_identity()
    if current_user['role'] not in ['SuperAdmin', 'CompanyAdmin']:
        return jsonify({'message': 'Permission denied'}), 403

    timeslot = Timeslot.query.get(timeslot_id)
    db.session.delete(timeslot)
    db.session.commit()
    return jsonify({'message': 'Timeslot deleted successfully'}), 200

@app.route('/reset_data/<company_id>', methods=['POST'])
@jwt_required()
def reset_data(company_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'SuperAdmin':
        return jsonify({'message': 'Permission denied'}), 403

    # Implement logic to reset data for the specified company
    return jsonify({'message': 'Data reset successfully'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

