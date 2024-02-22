from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_redis import FlaskRedis

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:h2ey6q8.RJDgWQaU7zyuXyqQ!!4yt.s3@localhost/py_shop'
db = SQLAlchemy(app)

jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'bosDs9yyCM48MVWHbaat'

app.config['REDIS_URL'] = 'redis://localhost:6379/1'
redis_store = FlaskRedis(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


@app.route('/', methods=['GET'])
def hello_world():
    return jsonify(message="Hello World!", code=0), 200


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "username or password required"}), 400

    user = User.query.filter_by(username=username).first()

    if user is not None:
        return jsonify({"message": "username already taken"}), 400

    new_user = User(username=username, password=generate_password_hash(password))

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user is None or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = create_access_token(identity=user.id)

    redis_store.set(user.id, access_token, ex=24 * 3600)

    return jsonify({"message": "Logged in successfully", "code": 0, "data": {
        "access_token": access_token
    }}), 200


@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    current_user_id = get_jwt_identity()
    redis_store.delete(current_user_id)

    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/change_password', methods=['POST'])
@jwt_required()
def change_password():
    data = request.get_json()
    username = data.get('username')
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        return jsonify({"message": "Old password and new password required"}), 400

    current_user = get_jwt_identity()
    user = User.query.filter_by(id=current_user).first()

    if user is None or not check_password_hash(user.password, old_password):
        return jsonify({"message": "Bad username or password"}), 401

    user.password = generate_password_hash(new_password)
    db.session.commit()

    return jsonify({"message": "Password changed successfully"}), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
