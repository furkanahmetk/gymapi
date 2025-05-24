from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_restx import Api, Resource, fields, abort
from decimal import Decimal
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/gym_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-change-this'  # Change this to a secure secret key

db = SQLAlchemy(app)
migrate = Migrate(app, db)
api = Api(app, version='1.0', title='Gym Course Scheduling API',
          description='API for managing gym courses, rooms, users, and schedules')


# ------------ AUTHENTICATION DECORATOR ----------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                abort(401, 'Invalid token format')

        if not token:
            abort(401, 'Token is missing')

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = Users.query.get(data['ssn'])
            if not current_user:
                abort(401, 'User not found')
        except jwt.ExpiredSignatureError:
            abort(401, 'Token has expired')
        except jwt.InvalidTokenError:
            abort(401, 'Invalid token')

        return f(current_user, *args, **kwargs)

    return decorated


# ------------ MODELS (Updated with password) ----------------

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
    'sign': fields.String(required=True, enum=['em', 'ea', 'rm', 'ra', 'am', 'aa'], description='Membership signature'),
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
        """Login user and get token"""
        data = api.payload

        user = Users.query.get(data['SSN'])
        if not user or not user.check_password(data['password']):
            abort(401, 'Invalid credentials')

        # Generate token
        token = jwt.encode({
            'ssn': user.SSN,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return {
            'token': token,
            'user': {
                'SSN': user.SSN,
                'firstName': user.firstName,
                'lastName': user.lastName,
                'membershipType': user.membershipType
            }
        }


# ------------ API ENDPOINTS (Updated with Authentication) -----------------

# -------- Membership Endpoints --------
@api.route('/memberships')
class MembershipList(Resource):
    @api.marshal_list_with(membership_model)
    def get(self):
        """Get all memberships"""
        return Membership.query.all()

    @api.expect(membership_model)
    @token_required
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

    @token_required
    def delete(self, current_user, sign):
        """Delete membership"""
        membership = Membership.query.get_or_404(sign)
        db.session.delete(membership)
        db.session.commit()
        return {'message': 'Membership deleted'}

    @api.expect(membership_model)
    @token_required
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
    @token_required
    def get(self, current_user):
        """Get all users"""
        return Users.query.all()


@api.route('/users/<string:ssn>')
class UsersResource(Resource):
    @api.marshal_with(user_model)
    @token_required
    def get(self, current_user, ssn):
        """Get user by SSN"""
        user = Users.query.get_or_404(ssn)
        return user

    @token_required
    def delete(self, current_user, ssn):
        """Delete user"""
        user = Users.query.get_or_404(ssn)
        db.session.delete(user)
        db.session.commit()
        return {'message': 'User deleted'}

    @api.expect(user_model)
    @token_required
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
    @token_required
    def get(self, current_user):
        """Get all phones"""
        return Phone.query.all()

    @api.expect(phone_model)
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
    @token_required
    def get(self, current_user, phone_number):
        """Get phone by number"""
        phone = Phone.query.get_or_404(phone_number)
        return phone

    @token_required
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
    @token_required
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

    @token_required
    def delete(self, current_user, ssn):
        """Delete instructor"""
        instructor = Instructors.query.get_or_404(ssn)
        db.session.delete(instructor)
        db.session.commit()
        return {'message': 'Instructor deleted'}

    @api.expect(instructor_model)
    @token_required
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
    @token_required
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

    @token_required
    def delete(self, current_user, room_id):
        """Delete room"""
        room = Room.query.get_or_404(room_id)
        db.session.delete(room)
        db.session.commit()
        return {'message': 'Room deleted'}

    @api.expect(room_model)
    @token_required
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
    @token_required
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

    @token_required
    def delete(self, current_user, course_name):
        """Delete course"""
        course = Course.query.get_or_404(course_name)
        db.session.delete(course)
        db.session.commit()
        return {'message': 'Course deleted'}

    @api.expect(course_model)
    @token_required
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
    @token_required
    def get(self, current_user):
        """Get all room schedules"""
        return RoomSchedule.query.all()

    @api.expect(roomschedule_model)
    @token_required
    def post(self, current_user):
        """Create a new room schedule"""
        data = api.payload
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
        return {'message': 'Room schedule created'}, 201


@api.route('/roomschedules/<int:schedule_id>')
class RoomScheduleResource(Resource):
    @api.marshal_with(roomschedule_model)
    @token_required
    def get(self, current_user, schedule_id):
        """Get room schedule by ID"""
        schedule = RoomSchedule.query.get_or_404(schedule_id)
        return schedule

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
    @token_required
    def get(self, current_user):
        """Get all user course enrollments"""
        return User_Course.query.all()

    @api.expect(user_course_model)
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
    @token_required
    def get(self, current_user):
        """Get all feedback"""
        return Feedback.query.all()

    @api.expect(feedback_model)
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
    @token_required
    def get(self, current_user, feedback_id):
        """Get feedback by ID"""
        feedback = Feedback.query.get_or_404(feedback_id)
        return feedback

    @token_required
    def delete(self, current_user, feedback_id):
        """Delete feedback"""
        feedback = Feedback.query.get_or_404(feedback_id)
        db.session.delete(feedback)
        db.session.commit()
        return {'message': 'Feedback deleted'}


# ------------ MAIN APPLICATION ----------------

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()

        from sqlalchemy import inspect

        inspector = inspect(db.engine)
        tables = inspector.get_table_names()

        # Create default memberships if they don't exist
        default_memberships = [
            {'sign': 'em', 'fee': 350.00, 'typeName': 'economy', 'plan': 'monthly'},
            {'sign': 'ea', 'fee': 4200.00, 'typeName': 'economy', 'plan': 'annual'},
            {'sign': 'rm', 'fee': 600.00, 'typeName': 'regular', 'plan': 'monthly'},
            {'sign': 'ra', 'fee': 7200.00, 'typeName': 'regular', 'plan': 'annual'},
            {'sign': 'am', 'fee': 900.00, 'typeName': 'advanced', 'plan': 'monthly'},
            {'sign': 'aa', 'fee': 9900.00, 'typeName': 'advanced', 'plan': 'annual'}
        ]

        for i, membership_data in enumerate(default_memberships):
            print(f"  Creating membership {i + 1}: {membership_data}")
            membership = Membership(**membership_data)
            db.session.add(membership)
            print(f"  ✅ Added to session: {membership.sign}")

        print("💾 Committing to database...")
        db.session.commit()

        # Create default rooms if they don't exist
        default_rooms = [
            {'roomName': 'Gym Floor'},
            {'roomName': 'Yoga Studio'},
            {'roomName': 'Pilates Room'},
            {'roomName': 'Cardio Zone'},
            {'roomName': 'Weight Room'}
        ]

        for room_data in default_rooms:
            if not Room.query.filter_by(roomName=room_data['roomName']).first():
                room = Room(**room_data)
                db.session.add(room)

        # Create a default admin user if it doesn't exist
        admin_ssn = "ADMIN123"
        if not Users.query.get(admin_ssn):
            admin_user = Users(
                SSN=admin_ssn,
                firstName="Admin",
                lastName="User",
                membershipType="aa"  # Advanced annual membership
            )
            admin_user.set_password("admin123")  # Default password
            db.session.add(admin_user)
            print("Default admin user created - SSN: ADMIN123, Password: admin123")

        try:
            db.session.commit()
            print("Database initialized successfully!")
            print("Default memberships and rooms created.")
        except Exception as e:
            db.session.rollback()
            print(f"Error initializing database: {e}")

    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)