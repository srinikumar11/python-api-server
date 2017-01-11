
from flask import *
from flask_security import http_auth_required, auth_token_required, Security, RoleMixin, UserMixin, SQLAlchemyUserDatastore
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
import datetime
import config

app = Flask(__name__)
CORS(app)
app.secret_key = config.SECRET_KEY
app.config['SECURITY_TRACKABLE'] = config.SECURITY_TRACKABLE
app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
app.config['SECURITY_PASSWORD_HASH'] = config.SECURITY_PASSWORD_HASH
app.config['SECURITY_PASSWORD_SALT'] = config.SECURITY_PASSWORD_SALT
app.config['WTF_CSRF_ENABLED'] = config.WTF_CSRF_ENABLED
app.config['SECURITY_TOKEN_MAX_AGE'] = config.SECURITY_TOKEN_MAX_AGE


db = SQLAlchemy(app)


from sqlalchemy.inspection import inspect

class Serializer(object):

    def serialize(self):
        return {c: getattr(self, c) for c in inspect(self).attrs.keys()}

    @staticmethod
    def serialize_list(l):
        return [m.serialize() for m in l]
        
# A base model for other database tables to inherit
class Base(db.Model, Serializer):
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    modified_at = db.Column(db.DateTime, default=db.func.current_timestamp(),
                            onupdate=db.func.current_timestamp())


roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(),
                                 db.ForeignKey('auth_user.id')),
                       db.Column('role_id', db.Integer(),
                                 db.ForeignKey('auth_role.id')))


class Role(Base, RoleMixin):
    __tablename__ = 'auth_role'
    name = db.Column(db.String(80), nullable=False, unique=True)
    description = db.Column(db.String(255))

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Role %r>' % self.name


class User(Base, UserMixin):
    __tablename__ = 'auth_user'
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(45))
    current_login_ip = db.Column(db.String(45))
    login_count = db.Column(db.Integer)
    user_search = db.Column(db.Text)
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    def __repr__(self):
        return '<User %r>' % self.email

    def serialize(self):
        d = Serializer.serialize(self)
        del d['password']
        return d

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


# Create a user to test with
@app.before_first_request
def create_user():
    db.create_all()
    if not User.query.first():
        user_datastore.create_user(email='test@example.com', password='test123')
        db.session.commit()



from flask_security import auth_token_required
from flask import jsonify

def unauth_handler():
    return Response(json.dumps({'message': 'please login.'}), 401)
security.unauthorized_handler(unauth_handler)


@app.route('/user', methods=['GET'])
@auth_token_required
def get_user():
    now = datetime.datetime.now()
    user = User.query.get(g.identity.user.id)
    ret_dict = {
        "Type": "Token",
        "Token": request.headers.get('Authentication-Token'),
        "Email": g.identity.user.email,
        "time": now,
        "user": user.serialize()
    }
    return jsonify(ret_dict)

@app.route('/user/save-search', methods=['POST'])
@auth_token_required
def save_search():
    now = datetime.datetime.now()
    user = User.query.get(g.identity.user.id)
    user.user_search = request.data
    db.session.commit()
    ret_dict = {
        "Type": "Token",
        "Token": request.headers.get('Authentication-Token'),
        "Email": g.identity.user.email,
        "time": now,
        "user": user.serialize()
    }
    return jsonify(ret_dict)


@app.route('/dummy-api-anonymous/', methods=['GET'])
@app.route('/', methods=['GET'])
def index():
    ret_dict = {
        "version": "1.0",
        "Email": "srinikumar11@gmail.com"
    }
    return jsonify(ret_dict)

@app.route('/logout')
def logout():
    logout_user()


app.run(port=5001, debug=True)
