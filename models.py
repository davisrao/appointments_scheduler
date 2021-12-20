"""SQLAlchemy models for AuthApp."""

from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

bcrypt = Bcrypt()
db = SQLAlchemy()


class User(db.Model):
    """User in the system."""

    __tablename__ = 'users'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    email = db.Column(
        db.Text,
        nullable=False,
        unique=True,
    )

    username = db.Column(
        db.Text,
        nullable=False,
        unique=True,
    )

    first_name = db.Column(
        db.Text,
        nullable=False,
    )

    last_name = db.Column(
        db.Text,
        nullable=False,
    )

    description = db.Column(
        db.Text,
        nullable=False,
    )

    role = db.Column(
        db.Text,
        nullable=False,
    )

    password = db.Column(
        db.Text,
        nullable=False,
    )

    def __repr__(self):
        return f"<User #{self.id}: {self.role}, {self.username}, {self.email}>"

    @classmethod
    def serialize(cls, self):
        """Serialize to dictionary"""
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "description": self.description,
            "role": self.role,
        }

    @classmethod
    def signup(cls, email, username, first_name,last_name,description,role,password):
        """Sign up user.

        Hashes password and adds user to system.
        """

        hashed_pwd = bcrypt.generate_password_hash(password).decode('UTF-8')

        user = User(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            description=description,
            role=role,
            password=hashed_pwd
        )

        db.session.add(user)
        db.session.commit()
        return user

    @classmethod
    def authenticate(cls, username, password):
        """Find user with `username` and `password`.

        This is a class method (call it on the class, not an individual user.)
        It searches for a user whose password hash matches this password
        and, if it finds such a user, returns that user object.

        If can't find matching user (or if password is wrong), returns False.
        """

        user = cls.query.filter_by(username=username).first()
        if user:
            is_auth = bcrypt.check_password_hash(user.password, password)
            if is_auth:
                return user

        return False


class Appointments(db.Model):
    """User in the system."""

    __tablename__ = 'appointments'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    coach = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete="cascade"),
        primary_key=True,
    )

    client = db.Column(
        db.Text,
        nullable=False,
        unique=False,
    )

    starts_at = db.Column(
        db.Time,
        nullable=False,
        unique=False,
    )

    duration = db.Column(
        db.Interval,
        nullable=False,
        unique=False,
    )

    def __repr__(self):
        return f"<Appointment for {self.coach}:{self.starts_at} {self.duration} minutes>"

    @classmethod
    def serialize(cls, self):
        """Serialize to dictionary"""
        return {
            "id": self.id,
            "coach": self.coach,
            "client": self.client,
            "starts_at": self.starts_at,
            "duration": self.duration,
        }


class Availabilities(db.Model):
    """User in the system."""

    __tablename__ = 'appointments'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    coach = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete="cascade"),
        primary_key=True,
    )

    client = db.Column(
        db.Text,
        nullable=False,
        unique=False,
    )

    starts_at = db.Column(
        db.Time,
        nullable=False,
        unique=False,
    )

    duration = db.Column(
        db.Interval,
        nullable=False,
        unique=False,
    )

    def __repr__(self):
        return f"<Availability for {self.coach}:{self.starts_at} {self.duration} minutes>"

    @classmethod
    def serialize(cls, self):
        """Serialize to dictionary"""
        return {
            "id": self.id,
            "coach": self.coach,
            "client": self.client,
            "starts_at": self.starts_at,
            "duration": self.duration,
        }




def connect_db(app):
    """Connect this database to provided Flask app.

    You should call this in your Flask app.
    """
    db.app = app
    db.init_app(app)