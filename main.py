from datetime import timedelta, datetime
import requests

from flask import Flask, jsonify, request, redirect, url_for
from pony.flask import Pony
from flask_socketio import SocketIO, send
from flask_jwt import JWT, jwt_required

from models import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'b30edca0886e00babec771d023155e'
Pony(app)

socketio = SocketIO(app, cors_allowed_origins='*')


@db_session
def authenticate(name, password):
    u = User.get(name=name)
    if bcrypt.checkpw(password.encode('UTF-8'), u.password):
        return u


@db_session
def identity(payload):
    user_id = payload['identity']
    u = User.get(id=user_id)
    return u


jwt = JWT(app, authenticate, identity)
app.config['JWT_EXPIRATION_DELTA'] = timedelta(seconds=3600)


@app.route('/users', methods=['GET'])
@db_session
def get_users():
    users = select(u for u in User)[:]
    out = []
    for u in users:
        u_names = {'id': u.id, 'name': u.name, 'nickname': u.nickname, 'age': u.age, 'password': str(u.password)}
        out.append(u_names)
    return jsonify({'users': out})


@app.route('/users/<id>', methods=['GET'])
@db_session
@jwt_required
def get_user(id):
    u = User.get(id=id)
    user_messages = select(u.messages.text for u in User if u.id == id)[:]
    user_income_messages = select(u.income_mess.text for u in User if u.id == id)[:]
    user_friends = select(u.friends.name for u in User if u.id == id)[:]
    out = []
    info = {'id': u.id, 'name': u.name, 'nickname': u.nickname, 'age': u.age, 'password': str(u.password),
            'registration_date': u.regdate, 'messages': str(user_messages),
            'income_messages': str(user_income_messages),
            'friends': str(user_friends)}
    out.append(info)
    return jsonify({'user': out})


@app.route('/user/<username>', methods=['GET'])
@db_session
def get_user_by_name(username):
    u = User.get(name=username)
    user_messages = select(u.messages.text for u in User if u.name == username)[:]
    user_income_messages = select(u.income_mess.text for u in User if u.name == username)[:]
    user_friends = select(u.friends.name for u in User if u.name == username)[:]
    out = []
    info = {'id': u.id, 'name': u.name, 'nickname': u.nickname, 'age': u.age, 'password': str(u.password),
            'registration_date': u.regdate, 'messages': str(user_messages),
            'income_messages': str(user_income_messages),
            'friends': str(user_friends)}
    out.append(info)
    return jsonify({'user': out})


@db_session
@app.route('/users', methods=['POST'])
def add_user():
    password = request.json['password']
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    user = User(name=request.json['name'], nickname=request.json['nickname'], age=request.json['age'],
                regdate=request.json['regdate'], password=hashed)
    return f'User {user.name} added successfully'


@db_session
@app.route('/messages', methods=['POST'])
@jwt_required()
def add_message():
    mes = Message(text=request.json['text'], mesdate=request.json['mesdate'], user=request.json['user'],
                  for_user=request.json['for_user'])
    return f'New message added successfully: {mes}'


@db_session
@app.route('/messages/<name>/<from_name>', methods=['GET'])
@jwt_required()
def get_message(name, from_name):
    mes = Message.select(lambda m: m.for_user.name == name and
                                   m.user.name == from_name).order_by(Message.mesdate)[:]
    out = []
    data = {'message': str(mes)}
    out.append(data)
    return {"messages": out}


@app.route('/users/<id>', methods=['PUT'])
@db_session
@jwt_required()
def update_user(id):
    password = request.json['password']
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    u = User.get(id=id)
    u.name = request.json['name']
    u.nickname = request.json['nickname']
    u.age = request.json['age']
    u.regdate = request.json['regdate']
    u.password = hashed
    return "User info updated successfully"


@db_session
@app.route('/login', methods=['GET', 'POST'])
def login():
    name = request.json['username']
    password = request.json['password']
    if not name or not password:
        return {"message": "There's no registered user with such name"}
    u = User.get(name=name)
    u_id = u.id
    if bcrypt.checkpw(password.encode('UTF-8'), u.password):
        return redirect(url_for('auth', username=name, password=password, id=u_id))
    else:
        return {'message': "Wrong password for this user"}


@app.route('/auth', methods=['GET', 'POST'])
def auth():
    username = request.args['username']
    password = request.args['password']
    uid = request.args['id']
    res = requests.post('http://127.0.0.1:5000/auth', json={'username': username, 'password': password})
    result = res.json()
    token = result['access_token']
    return {'token': token, 'id': uid}


@db_session
@socketio.on('message')
def handleMessage(data):
    print(f'Message: {data}')
    send(data, broadcast=True)
    date = datetime.utcnow()
    mesdate = f'{date.year}/{date.month}/{date.day}'
    message = Message(text=data['text'], mesdate=mesdate, user=data['user'], for_user=data['for_user'])


if __name__ == '__main__':
    app.run(debug=True)
