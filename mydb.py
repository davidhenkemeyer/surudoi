from sqlalchemy import create_engine, Column, Integer, String, MetaData, Table
from sqlalchemy.orm import sessionmaker, declarative_base
from passlib.hash import scrypt
from werkzeug.security import generate_password_hash, check_password_hash
import googlemaps
import argparse
import getpass

DATABASE_URL = 'sqlite:///instance/database.db'
# I enabled this from: https://console.cloud.google.com/google/maps-apis/home;onboard=true?project=praxis-zoo-440404-g7
GOOGLE_MAPS_API_KEY = 'AIzaSyB46UnqRfAn8i9dDCqTuUxmOdh99FXHcoc'  # Replace with your Google Maps API key

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()
metadata = MetaData()
Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    company_id = Column(Integer, nullable=False)
    role = Column(String, nullable=False)

class Location(Base):
    __tablename__ = 'location'
    id = Column(Integer, primary_key=True)
    address = Column(String, nullable=False)
    zip_code = Column(String, nullable=False)

def create_tables():
    Base.metadata.create_all(engine)

def add_user(username, company_id, role):
    password = getpass.getpass(prompt='Password: ')
    hashed_password = generate_password_hash(password, method='scrypt')
    new_user = User(username=username, password=hashed_password, company_id=company_id, role=role)
    session.add(new_user)
    session.commit()
    print(f"User {username} added successfully.")

def change_password(username):
    user = session.query(User).filter_by(username=username).first()
    if not user:
        print(f"User {username} not found.")
        return

    existing_password = getpass.getpass(prompt='Existing Password: ')
    if not check_password_hash(user.password, existing_password):
        print("Incorrect existing password.")
        return

    new_password = getpass.getpass(prompt='New Password: ')
    confirm_password = getpass.getpass(prompt='Confirm New Password: ')
    if new_password != confirm_password:
        print("Passwords do not match.")
        return

    user.password = generate_password_hash(new_password, method='scrypt')
    session.commit()
    print(f"Password for user {username} changed successfully.")

def verify_password(username):
    user = session.query(User).filter_by(username=username).first()
    if not user:
        print(f"User {username} not found.")
        return

    password = getpass.getpass(prompt='Password: ')
    if check_password_hash(user.password, password):
        print("Password is correct.")
    else:
        print("Password is incorrect.")

def get_gps_coordinates(location_id, address):
    gmaps = googlemaps.Client(key=GOOGLE_MAPS_API_KEY)
    if location_id is not None:
        location = session.query(Location).filter_by(id=location_id).first()
        if not location:
            print(f"Location with ID {location_id} not found.")
            return
        address_str = "{0}, {1}".format(location.address, location.zip_code)
    else:
        address_str = address
    #geocode_result = gmaps.geocode(location.address)
    geocode_result = gmaps.geocode(address_str)
    if geocode_result:
        loc = geocode_result[0]['geometry']['location']
        return loc['lat'], loc['lng']
    else:
        return "n/a", "n/a"

def add_record(table_name, fields):
    table = Table(table_name, metadata, autoload_with=engine)
    insert_stmt = table.insert().values(fields)
    print("This is the insert statement: {}".format(insert_stmt))
    session.execute(insert_stmt)
    session.commit()
    print(f"Record added to {table_name} successfully.")

def view_records(table_name):
    table = Table(table_name, metadata, autoload_with=engine)
    select_stmt = table.select()
    result = session.execute(select_stmt).fetchall()
    for row in result:
        print(row)

def get_records(table_name):
    table = Table(table_name, metadata, autoload_with=engine)
    select_stmt = table.select()
    result = session.execute(select_stmt).fetchall()
    return result

def delete_record(table_name, record_id):
    table = Table(table_name, metadata, autoload_with=engine)
    delete_stmt = table.delete().where(table.c.id == record_id)
    session.execute(delete_stmt)
    session.commit()
    print(f"Record with ID {record_id} deleted from {table_name} successfully.")

def modify_record(table_name, record_id, fields):
    table = Table(table_name, metadata, autoload_with=engine)
    update_stmt = table.update().where(table.c.id == record_id).values(fields)
    session.execute(update_stmt)
    session.commit()
    print(f"Record with ID {record_id} in {table_name} updated successfully.")

def show_tables():
    from sqlalchemy import inspect
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    for table in tables:
        print(table)

def describe_table(table_name):
    table = Table(table_name, metadata, autoload_with=engine)
    print(f"Description of table '{table_name}':")
    for column in table.columns:
        print(f"Column: {column.name}, Type: {column.type}, Not Null: {column.nullable}, Default Value: {column.default}, Primary Key: {column.primary_key}")

def add_location():
    companies = get_records("company")
    for company in companies:
        print("{0}: {1}".format(company.id, company.name))
    company_id = "-1"    
    while company_id not in [row.id for row in companies]:
        company_id = int(input('Company ID (required): '))
        if company_id not in [row.id for row in companies]:
            print("ID not valid")
    name = input('Name: ')
    addr = input('Street Address: ')
    city = input('City: ')
    state = input('State: ')
    zipcode = input('Zip Code: ')
    phonenum = input('Phone Number: ')
    email = input('Email address: ')
    mon_o = input('Monday Opening Time (e.g. 09:00:00): ')
    mon_c = input('Monday Closing Time (e.g. 16:00:00): ')
    tue_o = input('Tuesday Opening Time (e.g. 09:00:00): ')
    tue_c = input('Tuesday Closing Time (e.g. 16:00:00): ')
    wed_o = input('Wednesday Opening Time (e.g. 09:00:00): ')
    wed_c = input('Wednesday Closing Time (e.g. 16:00:00): ')
    thu_o = input('Thursday Opening Time (e.g. 09:00:00): ')
    thu_c = input('Thursday Closing Time (e.g. 16:00:00): ')
    fri_o = input('Friday Opening Time (e.g. 09:00:00): ')
    fri_c = input('Friday Closing Time (e.g. 16:00:00): ')
    sat_o = input('Saturday Opening Time (e.g. 09:00:00): ')
    sat_c = input('Saturday Closing Time (e.g. 16:00:00): ')
    sun_o = input('Sunday Opening Time (e.g. 09:00:00): ')
    sun_c = input('Sunday Closing Time (e.g. 16:00:00): ')
    fields = {}
    fields["company_id"] = company_id
    fields["name"] = name
    fields["address"] = addr
    fields["city"] = city
    fields["state"] = state
    fields["zip_code"] = zipcode
    fields["phone_number"] = phonenum
    fields["email_address"] = email
    fields["monday_open"] = mon_o
    fields["monday_close"] = mon_c
    fields["tuesday_open"] = tue_o
    fields["tuesday_close"] = tue_c
    fields["wednesday_open"] = wed_o
    fields["wednesday_close"] = wed_c
    fields["thursday_open"] = thu_o
    fields["thursday_close"] = thu_c
    fields["friday_open"] = fri_o
    fields["friday_close"] = fri_c
    fields["saturday_open"] = sat_o
    fields["saturday_close"] = sat_c
    fields["sunday_open"] = sun_o
    fields["sunday_close"] = sun_c
    fields["latitude"], fields["longitude"] = get_gps_coordinates(None, "{0}, {1}, {2}, {3}".format(addr, city, state, zipcode))
    print("Adding record with {0},{1}".format(fields["latitude"], fields["longitude"]))
    add_record("location", fields)
    
def main():
    create_tables()  # Ensure tables are created before any operations

    parser = argparse.ArgumentParser(description='Manage your database.')
    subparsers = parser.add_subparsers(dest='command')

    add_parser = subparsers.add_parser('add', help='Add a new record')
    add_parser.add_argument('table', help='Table name')
    add_parser.add_argument('fields', nargs='+', help='Fields for the new record')

    view_parser = subparsers.add_parser('view', help='View all records')
    view_parser.add_argument('table', help='Table name')

    delete_parser = subparsers.add_parser('delete', help='Delete a record')
    delete_parser.add_argument('table', help='Table name')
    delete_parser.add_argument('id', type=int, help='ID of the record to delete')

    modify_parser = subparsers.add_parser('modify', help='Modify a record')
    modify_parser.add_argument('table', help='Table name')
    modify_parser.add_argument('id', type=int, help='ID of the record to modify')
    modify_parser.add_argument('fields', nargs='+', help='Fields to update in the format field=value')

    show_tables_parser = subparsers.add_parser('tables', help='Show all tables')

    describe_table_parser = subparsers.add_parser('describe', help='Describe a table')
    describe_table_parser.add_argument('table', help='Table name')

    add_user_parser = subparsers.add_parser('add_user', help='Add a new user')
    add_user_parser.add_argument('username', help='Username')
    add_user_parser.add_argument('company_id', type=int, help='Company ID')
    add_user_parser.add_argument('role', help='Role (SuperAdmin, Admin, or User)')

    change_password_parser = subparsers.add_parser('changepw', help='Change user password')
    change_password_parser.add_argument('username', help='Username')

    verify_password_parser = subparsers.add_parser('verifypw', help='Verify user password')
    verify_password_parser.add_argument('username', help='Username')

    add_parser = subparsers.add_parser('add_location', help='Add a new location record')

    get_coordinates_parser = subparsers.add_parser('get_coordinates', help='Get GPS coordinates for a location')
    get_coordinates_parser.add_argument('location_id', type=int, help='Location ID')

    args = parser.parse_args()
    if args.command == 'add':
        fields = dict(field.split('=') for field in args.fields)
        add_record(args.table, fields)
    elif args.command == 'view':
        view_records(args.table)
    elif args.command == 'delete':
        delete_record(args.table, args.id)
    elif args.command == 'modify':
        fields = dict(field.split('=') for field in args.fields)
        modify_record(args.table, args.id, fields)
    elif args.command == 'tables':
        show_tables()
    elif args.command == 'describe':
        describe_table(args.table)
    elif args.command == 'add_user':
        add_user(args.username, args.company_id, args.role)
    elif args.command == 'add_location':
        add_location()
    elif args.command == 'changepw':
        change_password(args.username)
    elif args.command == 'verifypw':
        verify_password(args.username)
    elif args.command == 'get_coordinates':
        print("{0}".format(get_gps_coordinates(args.location_id, None)))

if __name__ == '__main__':
    main()
