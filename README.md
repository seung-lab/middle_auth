# Neuroglancer Auth

Authentication/authorization service to be used with Neuroglancer clients to connect to services such as a graph server that operate on the data being viewed. Uses OAuth2 to perform authentication on Google accounts. Constructs a key for the client which is also stored in redis. This key should be sent along with every request to a connected service requiring authentication using the Authorization header. 


curl "https://neuroglancer-auth.seunglab.org/test" -H "Authorization: INSERT_TOKEN"


The services requiring auth should respond with a 401 error when the provided token is missing from the request or missing from redis. This will inform the client that it needs to re-authenticate.

If the token is valid but the user is not authorized, the service should respond with a 403.

# deploying a new version
To trigger a new release of this package and increment the version number, please use bumpversion.  If not installed use `pip install bumpversion`.
To create a new release bumping the patch version, commit all your changes and then run
```
bumpversion patch && git push && git push --tags
```
which will increment the version and push those changes and the created tags to github.

