# Neuroglancer Auth

Authentication/authorization service to be used with Neuroglancer clients to connect to services such as a graph server that operate on the data being viewed. Uses OAuth2 to perform authentication on Google accounts. Constructs a key for the client which is also stored in redis. This key should be sent along with every request to a connected service requiring authentication using the Authorization header. 


curl "https://neuroglancer-auth.seunglab.org/test" -H "Authorization: INSERT_TOKEN"


The services requiring auth should respond with a 401 error when the provided token is missing from the request or missing from redis. This will inform the client that it needs to re-authenticate.

If the token is valid but the user is not authorized, the service should respond with a 403.
# Authorization model

### user
Users are assigned a unique user_id and associated with their google account when they login for the first time or when an super-admin creates there account using the admin panel. Super admin's have the right to create new groups, new datasets, and give groups permissions to datasets.

### group
Groups can be created ad hoc, and users can be assigned to be administrators of those groups.  Group administrators can add or remove users from that group.  Groups can be assigned arbitary string permissions to Datasets.  "view" and "edit" are the most used permissions by CAVE services. 

### dataset
Datasets are the top level data object that groups have permissions on. These strings are the unifying permissions model

### servicetable
Service tables are the mapping between the strings used by individual CAVE services to indicate different data objects and datasets.
Each servicetable entry has a "Service Name",  a "Table Name", and a "dataset".  In this way different services can have different namespaces for strings that segregate data that they control into different buckets.  This servicetable then unifies those different namespaces into one "dataset".

For example, the PychunkedGraph has a set of BigTable 'tables' whose names are different than the materialization service, which used the "datastack" name to segregrate data.  Entries for each Pychunkedgraph table string need to be entered with the "pychunkedgraph" service namespace and the 'dataset' they should be associated with.  

### permission
These are the unique strings that users are allowed to have.  "view", "edit" and "admin_view" are the default permissions, but it is extensible if services require more fine grain permisisons. 

### tos
These are optional terms of service that are associated with each dataset.  Users who have not signed the Terms of Service, will be required to do so before being granted permissions on that dataset. 

### User Affiliation
This is an optional mapping of users to institutions with start and end dates, meant to allow credit for user actions to be associated with institutions.

### app
This is list of the neuroglancer deployments that this auth service "trusts", this is a security feature of neuroglancer meant to prevent users from being tricked into providing their data to an untrusted application.  New deployments need to list the webpages that are allowed to forward requests to middle_auth. 




# deploying a new version
To trigger a new release of this package and increment the version number, please use bumpversion.  If not installed use `pip install bumpversion`.
To create a new release bumping the patch version, commit all your changes and then run
```
bumpversion patch && git push && git push --tags
```
which will increment the version and push those changes and the created tags to github.

