# Run a test server.
# import sys
from werkzeug.serving import WSGIRequestHandler
from neuroglancer_auth import create_app
import os

HOME = os.path.expanduser("~")

application = create_app()
