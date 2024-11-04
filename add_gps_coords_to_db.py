import requests
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

# Define the database URI
DATABASE_URI = 'sqlite:///instance\\database.db'

# Create a new SQLAlchemy engine
engine = create_engine(DATABASE_URI)

# Create a base class for declarative class definitions
Base = declarative_base()

# Define the Location model

class Company(Base):
    __tablename__ = 'company'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False)
    street_address = Column(String(120))
    city = Column(String(80))
    state = Column(String(80))
    zip_code = Column(String(20))
    phone_number = Column(String(20))
    locations = relationship('Location', backref='company', lazy=True)

class Location(Base):
    __tablename__ = 'location'
    id = Column(Integer, primary_key=True)
    name = Column(String(120))
    company_id = Column(Integer, ForeignKey('company.id'), nullable=False)
    address = Column(String(120))
    city = Column(String(80))
    state = Column(String(80))
    zip_code = Column(String(20))
    phone_number = Column(String(20))
    email_address = Column(String(80))
    monday_open = Column(String(10))
    monday_close = Column(String(10))
    tuesday_open = Column(String(10))
    tuesday_close = Column(String(10))
    wednesday_open = Column(String(10))
    wednesday_close = Column(String(10))
    thursday_open = Column(String(10))
    thursday_close = Column(String(10))
    friday_open = Column(String(10))
    friday_close = Column(String(10))
    saturday_open = Column(String(10))
    saturday_close = Column(String(10))
    sunday_open = Column(String(10))
    sunday_close = Column(String(10))
    latitude = Column(String(20), nullable=True)
    longitude = Column(String(20), nullable=True)

# Create a new session
Session = sessionmaker(bind=engine)
session = Session()

# Define the Google Maps API key
GOOGLE_MAPS_API_KEY = 'AIzaSyB46UnqRfAn8i9dDCqTuUxmOdh99FXHcoc'

# Function to get GPS coordinates using Google Maps API
def get_gps_coordinates(address):
    response = requests.get(
        'https://maps.googleapis.com/maps/api/geocode/json',
        params={'address': address, 'key': GOOGLE_MAPS_API_KEY}
    )
    data = response.json()
    
    if data['status'] == 'OK':
        coordinates = data['results'][0]['geometry']['location']
        return coordinates['lat'], coordinates['lng']
    
    return None, None

# Get all locations from the database
locations = session.query(Location).all()

# Update each location with GPS coordinates
for location in locations:
    address = f"{location.address}, {location.city}, {location.state}"
    print("Address is {}".format(address))
    latitude, longitude = get_gps_coordinates(address)
    
    print("This is latitude: {}".format(latitude))
    print("This is longitude: {}".format(longitude))
    if latitude and longitude:
        location.latitude = latitude
        location.longitude = longitude

# Commit the changes to the database
session.commit()

print("GPS coordinates have been added to all locations in the database.")

