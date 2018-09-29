# Run a test server.
# import sys
from werkzeug.serving import WSGIRequestHandler
from neuroglancer_auth import create_app
import os

HOME = os.path.expanduser("~")

application = create_app()

if __name__ == "__main__":

    WSGIRequestHandler.protocol_version = "HTTP/1.1"

    application.run(host='0.0.0.0',
                    port=4000,
                    debug=True,
                    threaded=True,
                    ssl_context='adhoc')
