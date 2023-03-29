from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from middle_auth_client import auth_required
import flask
import json
import os

from .model.base import r
from .model.app import App
from .model.cell_temp import CellTemp
from .model.user import User
from .model.group import Group
from .model.affiliation import Affiliation, UserAffiliation
from .model.tos import Tos
from .model.permission import Permission
from .model.dataset import Dataset
from .model.cell_temp import CellTemp
from .model.table_mapping import ServiceTable


TOKEN_NAME = os.environ.get("TOKEN_NAME", "middle_auth_token")


class SuperAdminView(ModelView):
    can_export = True

    def is_accessible(self):
        @auth_required
        def helper():
            return True

        return helper() and flask.g.get("auth_user", {}).get("admin", False)

    def inaccessible_callback(self, name, **kwargs):
        # redirect to login page if user doesn't have access
        return flask.redirect(flask.url_for("admin.index"))


# Create customized index view class that handles login & registration
class MyAdminIndexView(AdminIndexView):
    @expose("/", methods=["GET"])
    @auth_required
    def index(self):
        return super(MyAdminIndexView, self).index()

    def is_accessible(self):
        return True


def setup_admin(app, db):
    admin = Admin(
        app,
        name="middle auth admin",
        index_view=MyAdminIndexView(url="/sticky_auth/flask_admin"),
    )
    admin.add_view(SuperAdminView(User, db.session))
    admin.add_view(SuperAdminView(Group, db.session))
    admin.add_view(SuperAdminView(Affiliation, db.session))
    admin.add_view(SuperAdminView(UserAffiliation, db.session))
    admin.add_view(SuperAdminView(Dataset, db.session))
    admin.add_view(SuperAdminView(Permission, db.session))
    admin.add_view(SuperAdminView(Tos, db.session))
    admin.add_view(SuperAdminView(CellTemp, db.session))
    admin.add_view(SuperAdminView(ServiceTable, db.session))
    admin.add_view(SuperAdminView(App, db.session))
    return admin
