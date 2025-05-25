from flask import Flask, request, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_restx import Api, Resource, fields, abort
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt  # This will work after installing PyJWT
from datetime import datetime, timedelta
from functools import wraps
from flask import abort
from flask import Flask, request, render_template, make_response

"""
This file contains the Flask app configuration and API endpoints.
It also includes authentication and database models."""
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123@localhost/gym_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-change-this'  # Change this to a secure secret key
CORS(app)

# ------------ AUTHENTICATION model ----------------
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Type 'Bearer' followed by your token"
    }
}

# ------------ DB init ----------------
db = SQLAlchemy(app)
migrate = Migrate(app, db)
api = Api(app, version='1.0', title='Gym Course Scheduling API',
          description='API for managing gym courses, rooms, users, and schedules',
          authorizations=authorizations
          )


# ------------ AUTHENTICATION DECORATOR ----------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            abort(401, 'Token is missing')

        if is_token_blacklisted(token):
            abort(401, 'Token is blacklisted')

        try:
            # Decode the token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

            # Fetch the user from the database
            current_user = Users.query.get(data['ssn'])

            if not current_user:
                abort(401, 'User not found')

        except jwt.ExpiredSignatureError:
            abort(401, 'Token has expired')
        except jwt.InvalidTokenError:
            abort(401, 'Invalid token')

        # Pass the current_user to the next function
        return f(current_user, *args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        # Debugging logs to help trace the issue
        print(f"DEBUG: Admin Check for User: {current_user}")
        print(f"DEBUG: User Type: {type(current_user)}")
        print(f"DEBUG: User Attributes: {dir(current_user)}")

        # Check if the user is an admin
        if not current_user or not hasattr(current_user, 'membershipType') or current_user.membershipType != 'ad':
            abort(403, 'Admin privileges required')

        # Proceed to the next function
        return f(current_user, *args, **kwargs)

    return decorated


# ------------Logout Mechanism Functions----------------
def blacklist_token(token):
    blacklisted_token = Blacklist(token=token)
    db.session.add(blacklisted_token)
    db.session.commit()


def is_token_blacklisted(token):
    blacklisted = Blacklist.query.filter_by(token=token).first()
    return bool(blacklisted)


# ---------------Automatic activit creation function-----------

def create_activity(name, description, date, time, created_by):
    """
    Utility function to create an activity and save it to the database.
    """
    new_activity = Activities(
        name=name,
        description=description,
        date=date,
        time=time,
        created_by=created_by
    )
    db.session.add(new_activity)
    db.session.commit()


# ------------ MODELS (Updated with password) ----------------

class Blacklist(db.Model):
    __tablename__ = 'Blacklist'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, token):
        self.token = token


class Membership(db.Model):
    __tablename__ = 'Membership'
    sign = db.Column(db.String(2), primary_key=True)  # PRIMARY KEY
    fee = db.Column(db.Numeric(7, 2), nullable=False)  # Decimal(7,2)
    typeName = db.Column(db.String(10), nullable=False)
    plan = db.Column(db.String(8), nullable=False)

    def to_dict(self):
        return {
            'sign': self.sign,
            'fee': self.fee,
            'typeName': self.typeName,
            'plan': self.plan
        }


class Users(db.Model):
    __tablename__ = 'Users'
    SSN = db.Column(db.String(20), primary_key=True)
    firstName = db.Column(db.String(50), nullable=False)
    lastName = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  # Added password field
    membershipType = db.Column(db.String(2), db.ForeignKey('Membership.sign'))
    membership = db.relationship('Membership', backref='users')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Phone(db.Model):
    __tablename__ = 'Phone'
    phone = db.Column(db.String(20), primary_key=True)
    userSSN = db.Column(db.String(20), db.ForeignKey('Users.SSN', ondelete='CASCADE'))
    user = db.relationship('Users', backref='phones')


class Instructors(db.Model):
    __tablename__ = 'Instructors'
    SSN = db.Column(db.String(20), primary_key=True)
    firstName = db.Column(db.String(50), nullable=False)
    lastName = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))


class Room(db.Model):
    __tablename__ = 'Room'
    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    roomName = db.Column(db.String(20), nullable=False)


class Course(db.Model):
    __tablename__ = 'Course'
    courseName = db.Column(db.String(20), primary_key=True)
    capacity = db.Column(db.Numeric(2), nullable=False)
    isSpecial = db.Column(db.Boolean, nullable=False)
    InstructorID = db.Column(db.String(20), db.ForeignKey('Instructors.SSN'), nullable=False)
    roomId = db.Column(db.Integer, db.ForeignKey('Room.ID'), nullable=False)
    instructor = db.relationship('Instructors', backref='courses')
    room = db.relationship('Room', backref='courses')


class RoomSchedule(db.Model):
    __tablename__ = 'RoomSchedule'
    scheduleID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    roomId = db.Column(db.Integer, db.ForeignKey('Room.ID', ondelete='CASCADE'), nullable=False)
    scheduleDate = db.Column(db.Date, nullable=False)
    scheduleTime = db.Column(db.Time, nullable=False)
    bookingType = db.Column(db.String(10), nullable=False)
    userID = db.Column(db.String(20), db.ForeignKey('Users.SSN', ondelete='CASCADE'))
    courseName = db.Column(db.String(20), db.ForeignKey('Course.courseName', ondelete='CASCADE'))
    isBooked = db.Column(db.Boolean, nullable=False)
    room = db.relationship('Room', backref='schedules')
    user = db.relationship('Users', backref='room_bookings')
    course = db.relationship('Course', backref='room_schedules')


class User_Course(db.Model):
    __tablename__ = 'User_Course'
    courseName = db.Column(db.String(20), db.ForeignKey('Course.courseName', ondelete='CASCADE'), primary_key=True)
    userID = db.Column(db.String(20), db.ForeignKey('Users.SSN', ondelete='CASCADE'), primary_key=True)
    user = db.relationship('Users', backref='enrolled_courses')
    course = db.relationship('Course', backref='enrolled_users')


class Feedback(db.Model):
    __tablename__ = 'Feedback'
    feedBackNo = db.Column(db.Integer, primary_key=True, autoincrement=True)
    roomId = db.Column(db.Integer, db.ForeignKey('Room.ID', ondelete='CASCADE'), nullable=False)
    userID = db.Column(db.String(20), db.ForeignKey('Users.SSN', ondelete='CASCADE'), nullable=False)
    scheduleID = db.Column(db.Integer, db.ForeignKey('RoomSchedule.scheduleID', ondelete='CASCADE'), nullable=False)
    score = db.Column(db.Numeric(2, 1), nullable=False)
    comment = db.Column(db.String(200))
    room = db.relationship('Room', backref='feedbacks')
    user = db.relationship('Users', backref='feedbacks')
    schedule = db.relationship('RoomSchedule', backref='feedbacks')


class Activities(db.Model):
    __tablename__ = 'activities'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    created_by = db.Column(db.String(50), nullable=False)  # User SSN or unique identifier
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, name, description, date, time, created_by):
        self.name = name
        self.description = description
        self.date = date
        self.time = time
        self.created_by = created_by


# ------------ SWAGGER MODELS (Updated) ----------------

# Auth models
login_model = api.model('Login', {
    'SSN': fields.String(required=True, description='User SSN'),
    'password': fields.String(required=True, description='User password')
})

register_model = api.model('Register', {
    'SSN': fields.String(required=True, description='Social Security Number'),
    'firstName': fields.String(required=True, description='First name'),
    'lastName': fields.String(required=True, description='Last name'),
    'password': fields.String(required=True, description='Password'),
    'membershipType': fields.String(description='Membership type sign')
})

membership_model = api.model('Membership', {
    'sign': fields.String(required=True, enum=['em', 'ea', 'rm', 'ra', 'am', 'aa', 'ad', 'in'],
                          description='Membership signature'),
    'fee': fields.Float(required=True, description='Membership fee'),
    'typeName': fields.String(required=True, description='Type name (e.g., "economy")'),
    'plan': fields.String(required=True, description='Plan type (e.g., "monthly")')
})

user_model = api.model('Users', {
    'SSN': fields.String(required=True, description='Social Security Number'),
    'firstName': fields.String(required=True, description='First name'),
    'lastName': fields.String(required=True, description='Last name'),
    'membershipType': fields.String(description='Membership type sign')
})

phone_model = api.model('Phone', {
    'phone': fields.String(required=True, description='Phone number'),
    'userSSN': fields.String(description='User SSN')
})

instructor_model = api.model('Instructors', {
    'SSN': fields.String(required=True, description='Instructor SSN'),
    'firstName': fields.String(required=True, description='First name'),
    'lastName': fields.String(required=True, description='Last name'),
    'phone': fields.String(description='Phone number')
})

room_model = api.model('Room', {
    'ID': fields.Integer(readOnly=True, description='Room ID'),
    'roomName': fields.String(required=True, description='Room name')
})

course_model = api.model('Course', {
    'courseName': fields.String(required=True, description='Course name'),
    'capacity': fields.Integer(required=True, description='Course capacity'),
    'isSpecial': fields.Boolean(required=True, description='Is special course'),
    'InstructorID': fields.String(required=True, description='Instructor SSN'),
    'roomId': fields.Integer(required=True, description='Room ID')
})

roomschedule_model = api.model('RoomSchedule', {
    'scheduleID': fields.Integer(readOnly=True),
    'roomId': fields.Integer(required=True),
    'scheduleDate': fields.Date(required=True),
    'scheduleTime': fields.String(required=True),  # Time field as string
    'bookingType': fields.String(required=True, enum=['cleaning', 'class', 'private']),
    'userID': fields.String(description='User SSN for private bookings'),
    'courseName': fields.String(description='Course name for class bookings'),
    'isBooked': fields.Boolean(required=True)
})

user_course_model = api.model('User_Course', {
    'courseName': fields.String(required=True),
    'userID': fields.String(required=True, description='User SSN')
})

feedback_model = api.model('Feedback', {
    'feedBackNo': fields.Integer(readOnly=True),
    'roomId': fields.Integer(required=True),
    'userID': fields.String(required=True, description='User SSN'),
    'scheduleID': fields.Integer(required=True),
    'score': fields.Float(required=True, description='Rating score'),
    'comment': fields.String(description='Feedback comment')
})

activity_model = api.model('Activity', {
    'id': fields.Integer(readOnly=True, description='The unique identifier of the activity'),
    'name': fields.String(required=True, description='Activity name'),
    'description': fields.String(description='Activity description'),
    'date': fields.String(required=True, description='Activity date (YYYY-MM-DD)'),
    'time': fields.String(required=True, description='Activity time (HH:MM:SS)'),
    'created_by': fields.String(required=True, description='User SSN who created the activity'),
    'created_at': fields.String(readOnly=True, description='Timestamp when the activity was created')
})

create_activity_model = api.model('CreateActivity', {
    'name': fields.String(required=True, description='Activity name'),
    'description': fields.String(description='Activity description'),
    'date': fields.String(required=True, description='Activity date (YYYY-MM-DD)'),
    'time': fields.String(required=True, description='Activity time (HH:MM:SS)')
})


# ------------ BASIC ROUTES ----------------

@app.route('/')
def index():
    if 'user_id' in session:
        # If user is logged in, redirect to home
        user = Users.query.get(session['user_id'])

        return render_template('Home.html')
    # If no session exists, redirect to login
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Parse form data
        ssn = request.form.get('SSN')
        password = request.form.get('password')

        # Fetch user from the database
        user = Users.query.get(ssn)
        if not user or not user.check_password(password):
            return render_template('login.html', message='Invalid credentials'), 401

        # Set session
        session['user_id'] = user.SSN
        user = Users.query.get(session['user_id'])

        # Generate token
        token = jwt.encode({
            'ssn': user.SSN,
            'membershipType': user.membershipType,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        # If the user is an admin, load register.html
        if user.membershipType == 'ad':
            return render_template('register.html', user={
                'SSN': user.SSN,
                'firstName': user.firstName,
                'lastName': user.lastName,
                'membershipType': user.membershipType,
                'token': token
            })

        # Otherwise, load home page
        return render_template('Home.html', user={
            'SSN': user.SSN,
            'firstName': user.firstName,
            'lastName': user.lastName,
            'membershipType': user.membershipType,
            'token': token
        })

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        # Get form data
        ssn = request.form.get('SSN')
        password = request.form.get('password')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        membership_type = request.form.get('membershipType')
        phone_numbers = request.form.getlist('phoneNo')

        # Validate required fields
        if not ssn or not password or not first_name or not last_name:
            return render_template('register.html', current_user=user, message='All required fields must be filled out')

        # Check if user already exists
        if Users.query.get(ssn):
            return render_template('register.html', current_user=user, message='User with this SSN already exists')

        # Check if membership type exists
        if membership_type and not Membership.query.get(membership_type):
            return render_template('register.html', current_user=user, message='Selected membership type is not valid')

        print("np")
        # Create new user
        user = Users(
            SSN=ssn,
            firstName=first_name,
            lastName=last_name,
            membershipType=membership_type
        )
        user.set_password(password)

        # Add user to database
        db.session.add(user)

        # Add phone numbers if provided
        for phone in phone_numbers:
            if phone.strip():  # Only add non-empty phone numbers
                phone_entry = Phone(phone=phone, userSSN=ssn)
                db.session.add(phone_entry)

        # Commit changes to database
        try:
            db.session.commit()
            # Set session for the new user
            session['user_id'] = user.SSN
            # Redirect to home page after successful registration
            return render_template('register.html', current_user=user, message='Registration succeded')
        except Exception as e:
            db.session.rollback()
            return render_template('register.html', current_user=user, message=f'Registration failed: {str(e)}')

    # GET request - show registration form
    return render_template('register.html', current_user=user)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))


@app.route('/api/rooms')
def get_rooms():
    rooms = Room.query.all()
    return jsonify([{'id': room.ID, 'name': room.name} for room in rooms]), 200


@app.route('/api/courses')
def get_courses():
    courses = Course.query.all()
    return jsonify([{'name': course.courseName} for course in courses]), 200


# Admin booking sayfası için template render
@app.route('/booking_admin')
def booking_admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = Users.query.get(session['user_id'])
    rooms = Room.query.all()
    courses = Course.query.all()
    schedules = RoomSchedule.query.all()
    return render_template(
        'book_class_admin.html',
        rooms=rooms,
        courses=courses,
        roomSchedule=schedules
    )


# User booking sayfası için template render
@app.route('/booking_user')
def booking_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = db.session.get(Users, session['user_id'])

    rooms = Room.query.all()
    schedules = RoomSchedule.query.all()

    # Serialize rooms
    serialized_rooms = [
        {
            'id': room.ID,
            'name': room.roomName,
            # add any other fields you need
        } for room in rooms
    ]

    # Serialize schedules (if needed)
    serialized_schedules = [
        {
            'id': sched.id,
            'room_id': sched.room_id,
            'start_time': sched.start_time.isoformat(),  # if it's a datetime
            'end_time': sched.end_time.isoformat()
        } for sched in schedules
    ]

    return render_template(
        'book_class_user.html',
        rooms=serialized_rooms,
        roomSchedule=serialized_schedules,
        userSSN=current_user.SSN
    )


# Admin için özel booking endpoint'i
@app.route('/booking_admin', methods=['POST'])
def handle_admin_booking():
    data = request.get_json()
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = Users.query.get(session['user_id'])
    # Validasyonlar
    required_fields = ['roomId', 'scheduleDate', 'scheduleTime', 'courseName']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Tarih ve saat parsing
    try:
        schedule_date = datetime.strptime(data['scheduleDate'], '%Y-%m-%d').date()
        schedule_time = datetime.strptime(data['scheduleTime'], '%H:%M').time()
    except ValueError:
        return jsonify({'error': 'Invalid date/time format'}), 400

    # Mevcut booking kontrolü
    existing = RoomSchedule.query.filter_by(
        roomId=data['roomId'],
        scheduleDate=schedule_date,
        scheduleTime=schedule_time
    ).first()

    if existing:
        return jsonify({'error': 'Timeslot already booked'}), 409

    # Yeni booking oluştur
    new_booking = RoomSchedule(
        roomId=data['roomId'],
        scheduleDate=schedule_date,
        scheduleTime=schedule_time,
        bookingType='class',
        courseName=data['courseName'],
        isBooked=True
    )

    db.session.add(new_booking)
    db.session.commit()

    return jsonify({'message': 'Room booked successfully'}), 201


# User için özel booking endpoint'i
@app.route('/booking_user', methods=['POST'])
@token_required
def handle_user_booking(current_user):
    data = request.get_json()

    # Validasyonlar
    required_fields = ['roomId', 'scheduleDate', 'scheduleTime']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Tarih ve saat parsing
    try:
        schedule_date = datetime.strptime(data['scheduleDate'], '%Y-%m-%d').date()
        schedule_time = datetime.strptime(data['scheduleTime'], '%H:%M').time()
    except ValueError:
        return jsonify({'error': 'Invalid date/time format'}), 400

    # Mevcut booking kontrolü
    existing = RoomSchedule.query.filter_by(
        roomId=data['roomId'],
        scheduleDate=schedule_date,
        scheduleTime=schedule_time
    ).first()

    if existing:
        return jsonify({'error': 'Timeslot already booked'}), 409

    # Yeni booking oluştur
    new_booking = RoomSchedule(
        roomId=data['roomId'],
        scheduleDate=schedule_date,
        scheduleTime=schedule_time,
        bookingType='private',
        userID=current_user.SSN,
        isBooked=True
    )

    db.session.add(new_booking)
    db.session.commit()

    return jsonify({'message': 'Room booked successfully'}), 201


# Mevcut /roomschedules endpoint'ini güncelleme
@api.route('/roomschedules')
class RoomScheduleList(Resource):
    @api.marshal_list_with(roomschedule_model)
    def get(self):
        """Tüm odaların programını getir (JSON formatında)"""
        return RoomSchedule.query.all()


# ------------ BASIC ROUTES ----------------

@app.route('/')
def index():
    if 'user_id' in session:
        # If user is logged in, redirect to home
        user = Users.query.get(session['user_id'])

        return render_template('Home.html')
    # If no session exists, redirect to login
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Parse form data
        ssn = request.form.get('SSN')
        password = request.form.get('password')

        # Fetch user from the database
        user = Users.query.get(ssn)
        if not user or not user.check_password(password):
            return render_template('login.html', message='Invalid credentials'), 401

        # Set session
        session['user_id'] = user.SSN
        user = Users.query.get(session['user_id'])

        # Generate token
        token = jwt.encode({
            'ssn': user.SSN,
            'membershipType': user.membershipType,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        # If the user is an admin, load register.html
        if user.membershipType == 'ad':
            return render_template('register.html', user={
                'SSN': user.SSN,
                'firstName': user.firstName,
                'lastName': user.lastName,
                'membershipType': user.membershipType,
                'token': token
            })

        # Otherwise, load home page
        return render_template('Home.html', user={
            'SSN': user.SSN,
            'firstName': user.firstName,
            'lastName': user.lastName,
            'membershipType': user.membershipType,
            'token': token
        })

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        # Get form data
        ssn = request.form.get('SSN')
        password = request.form.get('password')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        membership_type = request.form.get('membershipType')
        phone_numbers = request.form.getlist('phoneNo')
        
        # Validate required fields
        if not ssn or not password or not first_name or not last_name:
            return render_template('register.html',current_user=user, message='All required fields must be filled out')
        
        # Check if user already exists
        if Users.query.get(ssn):
            return render_template('register.html',current_user=user, message='User with this SSN already exists')
        
        # Check if membership type exists
        if membership_type and not Membership.query.get(membership_type):
            return render_template('register.html', current_user=user, message='Selected membership type is not valid')
        
        print("np")
        # Create new user
        user = Users(
            SSN=ssn,
            firstName=first_name,
            lastName=last_name,
            membershipType=membership_type
        )
        user.set_password(password)
        
        # Add user to database
        db.session.add(user)
        
        # Add phone numbers if provided
        for phone in phone_numbers:
            if phone.strip():  # Only add non-empty phone numbers
                phone_entry = Phone(phone=phone, userSSN=ssn)
                db.session.add(phone_entry)
        
        # Commit changes to database
        try:
            db.session.commit()
            # Set session for the new user
            session['user_id'] = user.SSN
            # Redirect to home page after successful registration
            return render_template('register.html', current_user=user, message='Registration succeded')
        except Exception as e:
            db.session.rollback()
            return render_template('register.html', current_user=user, message=f'Registration failed: {str(e)}')
    
    # GET request - show registration form
    return render_template('register.html', current_user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))


@app.route('/api/rooms')
def get_rooms():
    rooms = Room.query.all()
    return jsonify([{'id': room.ID, 'name': room.name} for room in rooms]), 200

@app.route('/api/courses')
def get_courses():
    courses = Course.query.all()
    return jsonify([{'name': course.courseName} for course in courses]), 200

# Admin booking sayfası için template render
@app.route('/booking_admin')
def booking_admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = Users.query.get(session['user_id'])
    rooms = Room.query.all()
    courses = Course.query.all()
    schedules = RoomSchedule.query.all()
    return render_template(
        'book_class_admin.html',
        rooms=rooms,
        courses=courses,
        roomSchedule=schedules
    )

# User booking sayfası için template render
@app.route('/booking_user')
def booking_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = db.session.get(Users, session['user_id'])

    rooms = Room.query.all()
    schedules = RoomSchedule.query.all()

    # Serialize rooms
    serialized_rooms = [
        {
            'id': room.ID,
            'name': room.roomName,
            # add any other fields you need
        } for room in rooms
    ]

    # Serialize schedules (if needed)
    serialized_schedules = [
        {
            'id': sched.id,
            'room_id': sched.room_id,
            'start_time': sched.start_time.isoformat(),  # if it's a datetime
            'end_time': sched.end_time.isoformat()
        } for sched in schedules
    ]

    return render_template(
        'book_class_user.html',
        rooms=serialized_rooms,
        roomSchedule=serialized_schedules,
        userSSN=current_user.SSN
    )


# Admin için özel booking endpoint'i
@app.route('/booking_admin', methods=['POST'])

def handle_admin_booking():
    data = request.get_json()
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = Users.query.get(session['user_id'])
    # Validasyonlar
    required_fields = ['roomId', 'scheduleDate', 'scheduleTime', 'courseName']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Tarih ve saat parsing
    try:
        schedule_date = datetime.strptime(data['scheduleDate'], '%Y-%m-%d').date()
        schedule_time = datetime.strptime(data['scheduleTime'], '%H:%M').time()
    except ValueError:
        return jsonify({'error': 'Invalid date/time format'}), 400

    # Mevcut booking kontrolü
    existing = RoomSchedule.query.filter_by(
        roomId=data['roomId'],
        scheduleDate=schedule_date,
        scheduleTime=schedule_time
    ).first()
    
    if existing:
        return jsonify({'error': 'Timeslot already booked'}), 409

    # Yeni booking oluştur
    new_booking = RoomSchedule(
        roomId=data['roomId'],
        scheduleDate=schedule_date,
        scheduleTime=schedule_time,
        bookingType='class',
        courseName=data['courseName'],
        isBooked=True
    )
    
    db.session.add(new_booking)
    db.session.commit()
    
    return jsonify({'message': 'Room booked successfully'}), 201

# User için özel booking endpoint'i
@app.route('/booking_user', methods=['POST'])
@token_required
def handle_user_booking(current_user):
    data = request.get_json()
    
    # Validasyonlar
    required_fields = ['roomId', 'scheduleDate', 'scheduleTime']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Tarih ve saat parsing
    try:
        schedule_date = datetime.strptime(data['scheduleDate'], '%Y-%m-%d').date()
        schedule_time = datetime.strptime(data['scheduleTime'], '%H:%M').time()
    except ValueError:
        return jsonify({'error': 'Invalid date/time format'}), 400

    # Mevcut booking kontrolü
    existing = RoomSchedule.query.filter_by(
        roomId=data['roomId'],
        scheduleDate=schedule_date,
        scheduleTime=schedule_time
    ).first()
    
    if existing:
        return jsonify({'error': 'Timeslot already booked'}), 409

    # Yeni booking oluştur
    new_booking = RoomSchedule(
        roomId=data['roomId'],
        scheduleDate=schedule_date,
        scheduleTime=schedule_time,
        bookingType='private',
        userID=current_user.SSN,
        isBooked=True
    )
    
    db.session.add(new_booking)
    db.session.commit()
    
    return jsonify({'message': 'Room booked successfully'}), 201

# Mevcut /roomschedules endpoint'ini güncelleme
@api.route('/roomschedules')
class RoomScheduleList(Resource):
    @api.marshal_list_with(roomschedule_model)
    def get(self):
        """Tüm odaların programını getir (JSON formatında)"""
        return RoomSchedule.query.all()
# ------------ AUTHENTICATION ENDPOINTS ----------------

@api.route('/auth/register')
class Register(Resource):
    @api.expect(register_model)
    def post(self):
        """Register a new user"""
        data = api.payload

        # Check if user already exists
        if Users.query.get(data['SSN']):
            abort(400, 'User already exists')

        # Check if membership type exists
        if data.get('membershipType') and not Membership.query.get(data['membershipType']):
            abort(400, 'Membership type not found')

        # Create new user
        user = Users(
            SSN=data['SSN'],
            firstName=data['firstName'],
            lastName=data['lastName'],
            membershipType=data.get('membershipType')
        )
        user.set_password(data['password'])

        db.session.add(user)
        db.session.commit()

        return {'message': 'User registered successfully'}, 201


@api.route('/auth/login')
class Login(Resource):
    @api.expect(login_model)
    def post(self):
        if request.is_json:
            data = request.json
        else:
            data = request.form
        """Login user, generate token, and render template"""
        # Parse form data
        ssn = data.get('SSN')
        password = data.get('password')

        # Fetch user from the database
        user = Users.query.get(ssn)
        if not user or not user.check_password(password):
            # Render login page with error message for invalid credentials
            return render_template('login.html', message='Invalid credentials'), 401

        # Generate token
        token = jwt.encode({
            'ssn': user.SSN,
            'membershipType': user.membershipType,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        # Render dashboard template with user data and token
        return render_template('Home.html', user={
            'SSN': user.SSN,
            'firstName': user.firstName,
            'lastName': user.lastName,
            'membershipType': user.membershipType,
            'token': token
        })

@api.route('/auth/logout')
class Logout(Resource):
    @api.doc(security='Bearer')
    @token_required
    def post(self, current_user):
        """Logout user and blacklist the token"""
        # Extract the token from the Authorization header
        token = request.headers.get('Authorization').split(" ")[1]

        # Check if token is already blacklisted
        if is_token_blacklisted(token):
            abort(400, 'Token is already blacklisted')

        # Blacklist the token
        blacklist_token(token)
        return {'message': 'Successfully logged out'}, 200

# ------------ API ENDPOINTS (Updated with Authentication) -----------------

# -------- Membership Endpoints --------
@api.route('/memberships')
class MembershipList(Resource):
    @api.marshal_list_with(membership_model)
    def get(self):
        """Get all memberships"""
        return Membership.query.all()

    @api.expect(membership_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def post(self, current_user):
        """Create a new membership"""
        data = api.payload
        if Membership.query.get(data['sign']):
            abort(400, 'Membership already exists')
        membership = Membership(**data)
        db.session.add(membership)
        db.session.commit()
        return {'message': 'Membership created'}, 201


@api.route('/memberships/<string:sign>')
class MembershipResource(Resource):
    @api.marshal_with(membership_model)
    def get(self, sign):
        """Get membership by sign"""
        return Membership.query.get_or_404(sign)

    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def delete(self, current_user, sign):
        """Delete membership"""
        membership = Membership.query.get_or_404(sign)
        db.session.delete(membership)
        db.session.commit()
        return {'message': 'Membership deleted'}

    @api.expect(membership_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def put(self, current_user, sign):
        """Update membership"""
        membership = Membership.query.get_or_404(sign)
        data = api.payload
        membership.fee = data.get('fee', membership.fee)
        membership.typeName = data.get('typeName', membership.typeName)
        membership.plan = data.get('plan', membership.plan)
        db.session.commit()
        return {'message': 'Membership updated'}


# -------- User Endpoints --------
@api.route('/users')
class UsersList(Resource):
    @api.marshal_list_with(user_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def get(self, current_user):
        """Get all users"""
        return Users.query.all()


@api.route('/users/<string:ssn>')
class UsersResource(Resource):
    @api.marshal_with(user_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def get(self, current_user, ssn):
        """Get user by SSN"""
        user = Users.query.get_or_404(ssn)
        return user

    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def delete(self, current_user, ssn):
        """Delete user"""
        user = Users.query.get_or_404(ssn)
        db.session.delete(user)
        db.session.commit()
        return {'message': 'User deleted'}

    @api.expect(user_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def put(self, current_user, ssn):
        """Update user"""
        user = Users.query.get_or_404(ssn)
        data = api.payload
        user.firstName = data.get('firstName', user.firstName)
        user.lastName = data.get('lastName', user.lastName)
        if 'membershipType' in data:
            if data['membershipType'] and not Membership.query.get(data['membershipType']):
                abort(400, 'Membership type not found')
            user.membershipType = data['membershipType']
        db.session.commit()
        return {'message': 'User updated'}


# -------- Phone Endpoints --------
@api.route('/phones')
class PhoneList(Resource):
    @api.marshal_list_with(phone_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def get(self, current_user):
        """Get all phones"""
        return Phone.query.all()

    @api.expect(phone_model)
    @api.doc(security='Bearer')
    @token_required
    def post(self, current_user):
        """Create a new phone"""
        data = api.payload
        if Phone.query.get(data['phone']):
            abort(400, 'Phone number already exists')
        if data.get('userSSN') and not Users.query.get(data['userSSN']):
            abort(400, 'User not found')
        phone = Phone(**data)
        db.session.add(phone)
        db.session.commit()
        return {'message': 'Phone created'}, 201


@api.route('/phones/<string:phone_number>')
class PhoneResource(Resource):
    @api.marshal_with(phone_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def get(self, current_user, phone_number):
        """Get phone by number"""
        phone = Phone.query.get_or_404(phone_number)
        return phone

    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def delete(self, current_user, phone_number):
        """Delete phone"""
        phone = Phone.query.get_or_404(phone_number)
        db.session.delete(phone)
        db.session.commit()
        return {'message': 'Phone deleted'}


# -------- Instructor Endpoints --------
@api.route('/instructors')
class InstructorsList(Resource):
    @api.marshal_list_with(instructor_model)
    def get(self):
        """Get all instructors"""
        return Instructors.query.all()

    @api.expect(instructor_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def post(self, current_user):
        """Create a new instructor"""
        data = api.payload
        if Instructors.query.get(data['SSN']):
            abort(400, 'Instructor already exists')
        instructor = Instructors(**data)
        db.session.add(instructor)
        db.session.commit()
        return {'message': 'Instructor created'}, 201


@api.route('/instructors/<string:ssn>')
class InstructorsResource(Resource):
    @api.marshal_with(instructor_model)
    def get(self, ssn):
        """Get instructor by SSN"""
        instructor = Instructors.query.get_or_404(ssn)
        return instructor

    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def delete(self, current_user, ssn):
        """Delete instructor"""
        instructor = Instructors.query.get_or_404(ssn)
        db.session.delete(instructor)
        db.session.commit()
        return {'message': 'Instructor deleted'}

    @api.expect(instructor_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def put(self, current_user, ssn):
        """Update instructor"""
        instructor = Instructors.query.get_or_404(ssn)
        data = api.payload
        instructor.firstName = data.get('firstName', instructor.firstName)
        instructor.lastName = data.get('lastName', instructor.lastName)
        instructor.phone = data.get('phone', instructor.phone)
        db.session.commit()
        return {'message': 'Instructor updated'}


# -------- Room Endpoints --------
@api.route('/rooms')
class RoomList(Resource):
    @api.marshal_list_with(room_model)
    def get(self):
        """Get all rooms"""
        return Room.query.all()

    @api.expect(room_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def post(self, current_user):
        """Create a new room"""
        data = api.payload
        room = Room(roomName=data['roomName'])
        db.session.add(room)
        db.session.commit()
        return {'message': 'Room created'}, 201


@api.route('/rooms/<int:room_id>')
class RoomResource(Resource):
    @api.marshal_with(room_model)
    def get(self, room_id):
        """Get room by ID"""
        room = Room.query.get_or_404(room_id)
        return room

    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def delete(self, current_user, room_id):
        """Delete room"""
        room = Room.query.get_or_404(room_id)
        db.session.delete(room)
        db.session.commit()
        return {'message': 'Room deleted'}

    @api.expect(room_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def put(self, current_user, room_id):
        """Update room"""
        room = Room.query.get_or_404(room_id)
        data = api.payload
        room.roomName = data.get('roomName', room.roomName)
        db.session.commit()
        return {'message': 'Room updated'}


# -------- Course Endpoints --------
@api.route('/courses')
class CourseList(Resource):
    @api.marshal_list_with(course_model)
    def get(self):
        """Get all courses"""
        return Course.query.all()

    @api.expect(course_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def post(self, current_user):
        """Create a new course"""
        data = api.payload
        if Course.query.get(data['courseName']):
            abort(400, 'Course already exists')
        if not Instructors.query.get(data['InstructorID']):
            abort(400, 'Instructor not found')
        if not Room.query.get(data['roomId']):
            abort(400, 'Room not found')
        course = Course(**data)
        db.session.add(course)
        db.session.commit()
        return {'message': 'Course created'}, 201


@api.route('/courses/<string:course_name>')
class CourseResource(Resource):
    @api.marshal_with(course_model)
    def get(self, course_name):
        """Get course by name"""
        course = Course.query.get_or_404(course_name)
        return course

    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def delete(self, current_user, course_name):
        """Delete course"""
        course = Course.query.get_or_404(course_name)
        db.session.delete(course)
        db.session.commit()
        return {'message': 'Course deleted'}

    @api.expect(course_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def put(self, current_user, course_name):
        """Update course"""
        course = Course.query.get_or_404(course_name)
        data = api.payload
        course.capacity = data.get('capacity', course.capacity)
        course.isSpecial = data.get('isSpecial', course.isSpecial)
        if 'InstructorID' in data:
            if not Instructors.query.get(data['InstructorID']):
                abort(400, 'Instructor not found')
            course.InstructorID = data['InstructorID']
        if 'roomId' in data:
            if not Room.query.get(data['roomId']):
                abort(400, 'Room not found')
            course.roomId = data['roomId']
        db.session.commit()
        return {'message': 'Course updated'}


# -------- RoomSchedule Endpoints --------
@api.route('/roomschedules')
class RoomScheduleList(Resource):
    @api.marshal_list_with(roomschedule_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def get(self, current_user):
        """Get all room schedules"""
        return RoomSchedule.query.all()

    @api.expect(roomschedule_model)
    @api.doc(security='Bearer')
    @token_required
    def post(self, current_user):
        """Create a new room schedule"""
        data = api.payload
        if not Room.query.get(data['roomId']):
            abort(400, 'Room not found')

        # Validate room existence
        if not Room.query.get(data['roomId']):
            abort(400, 'Room not found')

        # Validate booking type constraints
        if data['bookingType'] == 'class' and not data.get('courseName'):
            abort(400, 'Course name required for class booking')
        if data['bookingType'] == 'private' and not data.get('userID'):
            abort(400, 'User ID required for private booking')
        if data['bookingType'] == 'class' and not Course.query.get(data['courseName']):
            abort(400, 'Course not found')
        if data['bookingType'] == 'private' and not Users.query.get(data['userID']):
            abort(400, 'User not found')

        schedule = RoomSchedule(**data)
        db.session.add(schedule)
        db.session.commit()

        # Automatically create an activity
        activity_name = f"Room Schedule: {data['bookingType'].capitalize()}"
        activity_description = f"Room {data['roomId']} scheduled for {data['bookingType']}"

        if data['bookingType'] == 'class':
            activity_description += f" (Course: {data['courseName']})"
        elif data['bookingType'] == 'private':
            user = Users.query.get(data['userID'])
            activity_description += f" (User: {user.firstName} {user.lastName})"

        create_activity(
            name=activity_name,
            description=activity_description,
            date=data['scheduleDate'],
            time=data['scheduleTime'],
            created_by=current_user.SSN
        )

        return {'message': 'Room schedule created and activity logged'}, 201


@api.route('/roomschedules/<int:schedule_id>')
class RoomScheduleResource(Resource):
    @api.marshal_with(roomschedule_model)
    @api.doc(security='Bearer')
    @token_required
    def get(self, current_user, schedule_id):
        """Get room schedule by ID"""
        schedule = RoomSchedule.query.get_or_404(schedule_id)
        return schedule

    @api.doc(security='Bearer')
    @token_required
    def delete(self, current_user, schedule_id):
        """Delete room schedule"""
        schedule = RoomSchedule.query.get_or_404(schedule_id)
        db.session.delete(schedule)
        db.session.commit()
        return {'message': 'Room schedule deleted'}


# -------- User_Course Endpoints --------
@api.route('/user_courses')
class UserCourseList(Resource):
    @api.marshal_list_with(user_course_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def get(self, current_user):
        """Get all user course enrollments"""
        return User_Course.query.all()

    @api.expect(user_course_model)
    @api.doc(security='Bearer')
    @token_required
    def post(self, current_user):
        """Enroll user in course"""
        data = api.payload
        if not Course.query.get(data['courseName']):
            abort(400, 'Course not found')
        if not Users.query.get(data['userID']):
            abort(400, 'User not found')

        # Check if already enrolled
        existing = User_Course.query.filter_by(
            courseName=data['courseName'],
            userID=data['userID']
        ).first()
        if existing:
            abort(400, 'User already enrolled in this course')

        enrollment = User_Course(**data)
        db.session.add(enrollment)
        db.session.commit()
        return {'message': 'User enrolled in course'}, 201


@api.route('/user_courses/<string:course_name>/<string:user_id>')
class UserCourseResource(Resource):
    @api.doc(security='Bearer')
    @token_required
    def delete(self, current_user, course_name, user_id):
        """Remove user from course"""
        enrollment = User_Course.query.filter_by(
            courseName=course_name,
            userID=user_id
        ).first_or_404()
        db.session.delete(enrollment)
        db.session.commit()
        return {'message': 'User removed from course'}


# -------- Feedback Endpoints --------
@api.route('/feedbacks')
class FeedbackList(Resource):
    @api.marshal_list_with(feedback_model)
    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def get(self, current_user):
        """Get all feedback"""
        return Feedback.query.all()

    @api.expect(feedback_model)
    @api.doc(security='Bearer')
    @token_required
    def post(self, current_user):
        """Create feedback"""
        data = api.payload
        if not Room.query.get(data['roomId']):
            abort(400, 'Room not found')
        if not Users.query.get(data['userID']):
            abort(400, 'User not found')
        if not RoomSchedule.query.get(data['scheduleID']):
            abort(400, 'Schedule not found')

        feedback = Feedback(**data)
        db.session.add(feedback)
        db.session.commit()
        return {'message': 'Feedback created'}, 201


@api.route('/feedbacks/<int:feedback_id>')
class FeedbackResource(Resource):
    @api.marshal_with(feedback_model)
    @api.doc(security='Bearer')
    @token_required
    def get(self, current_user, feedback_id):
        """Get feedback by ID"""
        feedback = Feedback.query.get_or_404(feedback_id)
        return feedback

    @api.doc(security='Bearer')
    @token_required
    @admin_required
    def delete(self, current_user, feedback_id):
        """Delete feedback"""
        feedback = Feedback.query.get_or_404(feedback_id)
        db.session.delete(feedback)
        db.session.commit()
        return {'message': 'Feedback deleted'}


# ------------ ACTIVITIES ----------------
@api.route('/activities')
class ActivitiesResource(Resource):
    @api.marshal_with(activity_model, as_list=True)
    @api.doc(security='Bearer')
    @token_required
    def get(self, current_user):
        """Get all activities"""
        activities = Activities.query.all()
        return activities

    @api.expect(create_activity_model)
    @api.doc(security='Bearer')
    @token_required
    def post(self, current_user):
        """Create a new activity"""
        data = api.payload

        # Create a new activity
        activity = Activities(
            name=data['name'],
            description=data.get('description'),
            date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
            time=datetime.strptime(data['time'], '%H:%M:%S').time(),
            created_by=current_user.ssn  # Assuming `ssn` is a field in the `Users` model
        )

        db.session.add(activity)
        db.session.commit()

        return {'message': 'Activity created successfully'}, 201


@api.route('/activities/index')
class ActivityIndexResource(Resource):
    @api.marshal_with(activity_model, as_list=True)
    @api.doc(security='Bearer')
    @token_required
    def get(self, current_user):
        """Get activities for the current or specified month"""
        # Parse query parameters for month and year
        month = request.args.get('month', datetime.utcnow().month, type=int)
        year = request.args.get('year', datetime.utcnow().year, type=int)

        # Fetch activities for the specified month and year
        activities = Activities.query.filter(
            db.extract('month', Activities.date) == month,
            db.extract('year', Activities.date) == year
        ).all()

        return activities


# ------------ INDEX ----------------
@api.route('/index')
class IndexResource(Resource):
    @api.doc(security='Bearer', params={'user_id': 'Optional user ID to filter activities'})
    @token_required
    def get(self, current_user):
        """Get all activities or activities of a specific user"""
        user_id = request.args.get('user_id', type=int)

        if user_id:
            activities = Activities.query.filter_by(user_id=user_id).all()
        else:
            activities = Activities.query.all()

        return make_response(render_template('Home.html', activities=activities), 200, {'Content-Type': 'text/html'})


# ------------ MAIN APPLICATION ----------------

if __name__ == '__main__':
    with app.app_context():
        # db.drop_all()
        # Create all tables if they don't exist
        db.create_all()

        # Check if tables are empty before populating them
        if not Membership.query.first():
            # Create default memberships if they don't exist
            default_memberships = [
                {'sign': 'em', 'fee': 350.00, 'typeName': 'economy', 'plan': 'monthly'},
                {'sign': 'ea', 'fee': 4200.00, 'typeName': 'economy', 'plan': 'annual'},
                {'sign': 'rm', 'fee': 600.00, 'typeName': 'regular', 'plan': 'monthly'},
                {'sign': 'ra', 'fee': 7200.00, 'typeName': 'regular', 'plan': 'annual'},
                {'sign': 'am', 'fee': 900.00, 'typeName': 'advanced', 'plan': 'monthly'},
                {'sign': 'aa', 'fee': 9900.00, 'typeName': 'advanced', 'plan': 'annual'},
                {"sign": "ad", "fee": 0, "typeName": "admin", "plan": "none"},
                {"sign": "in", "fee": 0, "typeName": "instructor", "plan": "none"}
            ]

            for membership_data in default_memberships:
                membership = Membership(**membership_data)
                db.session.add(membership)

            print("Default memberships created.")

        if not Room.query.first():
            # Create default rooms if they don't exist
            default_rooms = [
                {'roomName': 'Gym Floor'},
                {'roomName': 'Yoga Studio'},
                {'roomName': 'Pilates Room'},
                {'roomName': 'Cardio Zone'},
                {'roomName': 'Weight Room'}
            ]

            for room_data in default_rooms:
                room = Room(**room_data)
                db.session.add(room)

            print("Default rooms created.")

        # Create a default admin user if it doesn't exist
        admin_ssn = "ADMIN123"
        if not Users.query.get(admin_ssn):
            admin_user = Users(
                SSN=admin_ssn,
                firstName="Admin",
                lastName="User",
                membershipType="ad"
            )
            admin_user.set_password("admin123")
            db.session.add(admin_user)
            print("Default admin user created - SSN: ADMIN123, Password: admin123")

        try:
            db.session.commit()
            print("Database initialized successfully!")
        except Exception as e:
            db.session.rollback()
            print(f"Error initializing database: {e}")

    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5001)