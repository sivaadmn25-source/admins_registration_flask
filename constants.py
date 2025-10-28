import os
from dotenv import load_dotenv

load_dotenv()

# Define standard application constants
house_type = {
    "Apartment-Single Tower",
    "Villas-Lanes",
    "Villas-No Lanes",
    "Apartment-Multi Towers",
    "Civil - Bodies"
}

# For local development, default to localhost
BASE_URL = os.environ.get('APP_DOMAIN', 'http://localhost:5000')
LOGIN_URL = os.environ.get('LOGIN_URL', f'{BASE_URL}/system-entry')
