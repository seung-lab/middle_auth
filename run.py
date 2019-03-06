# Run a test server.
# import sys
# from werkzeug.serving import WSGIRequestHandler
# from neuroglancer_auth import create_app
# import os

# HOME = os.path.expanduser("~")

# application = create_app()

# from gevent import pywsgi
# from geventwebsocket.handler import WebSocketHandler
# server = pywsgi.WSGIServer(('', 5000), application, handler_class=WebSocketHandler)
# server.serve_forever()


from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "https://developer.mozilla.org"}})

@app.route("/")
def helloWorld():
	return "Hello, cross-origin-world!"
