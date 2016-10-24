import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from jwt import encode, decode
from jose.exceptions import JWSError
from passlib.context import CryptContext
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String


app = Flask(__name__)

# Enable cross-origin requests
CORS(app)

# Set up the database, using configuration if available:
if "DATABASE_URL" in os.environ:
    database_url = os.environ["DATABASE_URL"]
else:
    database_url = "sqlite:////tmp/ons.db"
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
db = SQLAlchemy(app)


# User model
class User(db.Model):

    # Columns
    id = Column(Integer, primary_key=True)
    user_id = Column(String(10))
    name = Column(String(255))
    email = Column(String(255), unique=True)
    password_hash = Column(String(255))

    # Password handling
    # "PBKDF2 is probably the best for portability"
    #  http://pythonhosted.org/passlib/new_app_quickstart.html
    pwd_context = CryptContext(schemes=["pbkdf2_sha256"], default="pbkdf2_sha256")

    def __init__(self, user_id=None, name=None, email=None):
        self.user_id = user_id
        self.name = name
        self.email = email

    def __repr__(self):
        return '<User %r>' % self.name

    def json(self):
        return {"user_id": self.user_id,
                "name": self.name,
                "email": self.email}

    def set_password(self, password):
        self.password_hash = None
        if password is not None:
            self.password_hash = self.pwd_context.encrypt(password)

    def verify_password(self, password):
        """ Users can't log in until a password is set. """
        return self.password_hash is not None and \
            self.pwd_context.verify(password, self.password_hash)


@app.route('/', methods=['GET'])
def info():
    return """
        </ul>
            <li>Try POST to <a href="/login">/login</a></li>
            <li>Valid email addresses are:
            nick.gravgaard@example.com
            shane.edwards@example.com and
            david.carboni@example.com
            </li>
            <li>Make a note of the returned token and pass it in a "token" header for other requests.</li>
            <li>Try GET or POST to <a href="/profile">/profile</a></li>
        </ul>
        """


@app.route('/login', methods=['POST'])
def login():
    credentials = request.get_json()

    if credentials and ("email" in credentials) and ("password" in credentials):
        user = User.query.filter_by(email=credentials["email"]).first()
        if user is not None:
            if user.verify_password(credentials["password"]):
                token = encode(user.json())
                return jsonify({"token": token})
        return unauthorized("Access denied")
    else:
        return unauthorized("Please provide a Json message with 'email' and 'password' fields.")


@app.route('/profile', methods=['GET'])
def profile():
    token = request.headers.get("token")
    data = validate_token(token)

    if data and "user_id" in data:
        # We have a verified user id:
        user = User.query.filter_by(user_id=data["user_id"]).first()
        if user is not None:
            return jsonify(user.json())
        return known_error("Respondent ID " + str(data["user_id"]) + " not found.")
    return unauthorized("Please provide a token header that includes a user_id.")


@app.route('/profile', methods=['POST'])
def profile_update():
    token = request.headers.get("token")
    data = validate_token(token)
    json = request.get_json()

    if data and "user_id" in data:
        # We have a verified user id:
        user = User.query.filter_by(user_id=data["user_id"]).first()
        if user is not None:
            if "name" in json:
                user.name = json["name"]
                db.session.commit()
            return jsonify(user.json())
        return known_error("Respondent ID " + str(data["user_id"]) + " not found.")
    return unauthorized("Please provide a token header that includes a user_id.")


@app.errorhandler(401)
def unauthorized(error=None):
    app.logger.error("Unauthorized: '%s'", request.data.decode('UTF8'))
    message = {
        'message': "{}: {}".format(error, request.url),
    }
    resp = jsonify(message)
    resp.status_code = 401

    return resp


@app.errorhandler(400)
def known_error(error=None):
    app.logger.error("Bad request: '%s'", request.data.decode('UTF8'))
    message = {
        'message': "{}: {}".format(error, request.url),
    }
    resp = jsonify(message)
    resp.status_code = 400

    return resp


@app.errorhandler(500)
def unknown_error(error=None):
    app.logger.error("Error: '%s'", request.data.decode('UTF8'))
    message = {
        'message': "Internal server error: " + repr(error),
    }
    resp = jsonify(message)
    resp.status_code = 500

    return resp


def validate_token(token):

    if token:
        try:
            return decode(token)
        except JWSError:
            return ""


def create_database():

    #print("Dropping tables...")
    #db.drop_all()
    print("Creating tables...")
    db.create_all()
    print("Done")


def create_users():

    # Set up users
    users = [
        {
            "user_id": "101",
            "email": "nick.gravgaard@example.com",
            "name": "Nick Gravgaard",
        },
        {
            "user_id": "102",
            "email": "shane.edwards@example.com",
            "name": "Shane Edwards",
        },
        {
            "user_id": "103",
            "email": "david.carboni@example.com",
            "name": "David Carboni",
        },
        {
            "user_id": "104",
            "email": "nic.price@example.com",
            "name": "Nic Price",
        },
        {
            "user_id": "105",
            "email": "rich.ingram@example.com",
            "name": "Rich Ingram",
        },
        {
            "user_id": "106",
            "email": "tom.underwood@example.com",
            "name": "Tom Underwood",
        },
        {
            "user_id": "107",
            "email": "rachel.williams@example.com",
            "name": "Rachel Williams",
        },
        {
            "user_id": "108",
            "email": "nige.sedgwich@example.com",
            "name": "Nige Sedgwick",
        },
        {
            "user_id": "109",
            "email": "simon.houghton@example.com",
            "name": "Simon Houghton",
        },
        {
            "user_id": "110",
            "email": "rob.kent@example.com",
            "name": "Rob Kent",
        }
    ]
    for user in users:
        if User.query.filter_by(user_id=user["user_id"]).first() is None:
            account = User(
                user_id=user["user_id"],
                email=user["email"],
                name=user["name"]
            )
            account.set_password("password")
            db.session.add(account)
            db.session.commit()
            print(account)

    # Just to see that test users are present
    print(User.query.all())


if __name__ == '__main__':

    # Create database
    print("creating database")
    create_database()
    print("creating users")
    create_users()
    print("End of setup")

    # Start server
    print("Getting port...")
    port = int(os.environ.get("PORT", 5000))
    print("Port is " + str(port))
    print("running...")
    app.run(debug=True, host='0.0.0.0', port=port)
