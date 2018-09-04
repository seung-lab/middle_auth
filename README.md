# Neuroglancer Auth

Authentication/authorization service to be used with Neuroglancer clients to connect to services such as a graph server that operate on the data being viewed. Uses OAuth2 to perform authentication on Google accounts. Constructs a key for the client which is also stored in redis. This key should be sent along with every request to a connected service requiring authentication using the Authorization header. 


curl "https://neuroglancer-auth.seunglab.org/test" -H "Authorization: INSERT_TOKEN"