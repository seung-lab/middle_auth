# Run a test server.
# import sys
from werkzeug.serving import WSGIRequestHandler
from neuroglancer_auth import create_app
import os
import sys

HOME = os.path.expanduser("~")

application = create_app()

print(os.environ)
print(sys.argv)

# from gevent import pywsgi
# from geventwebsocket.handler import WebSocketHandler
# server = pywsgi.WSGIServer(('', 4000), application, handler_class=WebSocketHandler)
# server.serve_forever()
