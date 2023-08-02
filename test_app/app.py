import os
import inspect
import sys
# Add correct directory to sys.path
_BASE_DIR = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe()))
)

sys.path.insert(0, _BASE_DIR + "/../deps/protobuf/python/")

import json
from flask import Flask, request
from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint
from sqlalchemy.engine import Engine
from google.protobuf.json_format import MessageToJson, Parse
import addressbook_pb2

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
api = Api(app)
db = SQLAlchemy(app)

@db.event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()

class PersonModel(db.Model):
    __tablename__ = 'person'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True)
    phones = db.relationship('PhoneModel', backref='person', lazy=True)

class PhoneModel(db.Model):
    __tablename__ = 'phone'
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(50), nullable=False)
    type = db.Column(db.String(50))
    person_id = db.Column(db.Integer, db.ForeignKey('person.id'), nullable=False)


with app.app_context():
    db.create_all()


PHONE_TYPE_MAP = {
    "0": "PHONE_TYPE_UNSPECIFIED",
    "1": "PHONE_TYPE_MOBILE",
    "2": "PHONE_TYPE_HOME",
    "3": "PHONE_TYPE_WORK"
}

class AddressBook(Resource):
    def get(self):
        people = PersonModel.query.all()
        address_book = addressbook_pb2.AddressBook()
        for person in people:
            p = addressbook_pb2.Person(name=person.name, id=person.id, email=person.email)
            for phone in person.phones:
                phone_type_label = PHONE_TYPE_MAP[phone.type]
                p.phones.add(number=phone.number, type=phone_type_label)
            address_book.people.append(p)
        json_dict = json.loads(MessageToJson(address_book))
        return json_dict, 200

    def post(self):
        address_book = addressbook_pb2.AddressBook()
        address_book.ParseFromString(request.data)
        for person in address_book.people:
            p = PersonModel(name=person.name, id=person.id, email=person.email)
            for phone in person.phones:
                p.phones.append(PhoneModel(number=phone.number, type=phone.type))
            db.session.add(p)
        db.session.commit()
        return 'Added', 201


api.add_resource(AddressBook, '/addressbook')


if __name__ == '__main__':
    app.run(debug=True)

