"""Entry point for `flask run` (and WSGI servers: `waitress-serve app:app`)."""
from surudoi import create_app

app = create_app()
