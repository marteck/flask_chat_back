from datetime import date
import bcrypt
from pony.orm.core import *

db = Database()
db.bind(provider='sqlite', filename='testbase.db', create_db=True)


class User(db.Entity):
    id = PrimaryKey(int, auto=True)
    name = Required(str)
    friends = Set('User', reverse='friends')
    nickname = Optional(str)
    regdate = Required(date)
    password = Required(bytes)
    age = Optional(int)
    messages = Set('Message', reverse='user')
    income_mess = Set('Message', reverse='for_user')

    def __repr__(self):
        return f'{self.name}/{self.nickname}/{self.regdate}/{self.password}'


class Message(db.Entity):
    id = PrimaryKey(int, auto=True)
    text = Optional(str)
    mesdate = Required(date)
    user = Required(User, reverse='messages')
    for_user = Required(User, reverse='income_mess')

    def __repr__(self):
        return f'{self.text}'  # /{self.mesdate}/{self.user.name} sent to {self.for_user.name}'


db.generate_mapping(create_tables=True)


def hash_pass(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


@db_session
def update_db():
    if select(u for u in User).count() > 0:
        pass
    else:
        u1 = User(name='sasha', nickname="alexa", age=15, regdate='01/01/2021', password=hash_pass('qwerty'))
        u2 = User(name='vasia', nickname="vaivasia", age=13, regdate='01/02/2021', password=hash_pass('qy'))
        u3 = User(name='lesha', nickname="lex", age=12, regdate='03/02/2021', password=hash_pass('qhjk'))
        u4 = User(name='marat', nickname="maratttq", age=14, regdate='11/01/2021', password=hash_pass('qty'))
        u1.friends = [u2, u3, u4]
        u2.friends = [u1, u3]
        u3.friends = [u1]
        u4.friends = [u1]
        mes1 = Message(text='atatata', mesdate='01/01/2021', user=u2, for_user=u1)
        mes2 = Message(text='hello', mesdate='01/02/2021', user=u3, for_user=u2)
        mes3 = Message(text='ho-ho', mesdate='03/02/2021', user=u1, for_user=u2)
        mes4 = Message(text='wtf', mesdate='11/01/2021', user=u1, for_user=u4)
        mes5 = Message(text='brwkghjfgyj', mesdate='05/02/2021', user=u4, for_user=u1)
        u1.messages.add([mes3, mes4])
        u2.messages.add(mes1)
        u3.messages.add(mes2)
        u4.messages.add(mes5)


@db_session
def test_queries():
    result = select(u.friends.name for u in User if u.name == 'vasia')[:]
    print(result)

    result = select(u.name for u in User if not u.income_mess)[:]
    print(result)

    result = select(u.messages.text for u in User if u.name == 'sasha')[:]
    print(result)

    # result = User(name='vasia', nickname="vaivasia", age=13, regdate='01/02/2021', password='qy')
    # print(result)

    um = Message[4]
    print(um)

    message_list = Message.select(lambda m: len(m.text) == 3)[:]
    print(message_list)

    userid_less_than = User.select(lambda u: u.id < 4)[:]
    print(userid_less_than)

    exact_message = Message.get(id=2)
    print(exact_message.user.name)

    result = Message.select().order_by(desc(Message.mesdate))[:3]
    print(result)

    result = list(select(u.income_mess for u in User if u.name == 'sasha').order_by(Message.mesdate))[-1]
    print(result)

    db.rollback()

    result = select(u.name for u in User)[:]
    print(result)

    message_list = Message.select(lambda m: m.for_user.name == 'marat' and
                                m.user.name == 'sasha').order_by(Message.mesdate)[:]
    cons = ['message']
    result = dict.fromkeys(cons, message_list)
    print(result)


if __name__ == '__main__':
    update_db()
    test_queries()

# db.drop_all_tables(with_all_data=True)
