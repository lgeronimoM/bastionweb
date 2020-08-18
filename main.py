#!/usr/bin/env python
__author__ = 'Luis Geronimo'
# APP principal
from app import app, cf, db, login_manager

#packages log
import logging
from datetime import datetime

#Flask admin
from flask_admin import Admin, BaseView, expose, AdminIndexView
from flask_admin.contrib.sqla import ModelView

#models
from app.models import Servers, Users, Access, Bastion, AdminView

#logs
LOG_FILENAME = datetime.now().strftime(cf.LOG_DIR)
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(filename=LOG_FILENAME,level=cf.LOG_LEVEL)
logging.info('Comenzando la aplicacion...')

############################## Admin ###################################
@login_manager.user_loader
def load_user(id):
    return Users.query.get(id)

admin = Admin(app, url=cf.LINK, index_view=AdminView(), name=cf.NAMEAPP, template_mode=cf.TEM)
#admin = Admin(app, url=cf.LINK, name=cf.NAMEAPP, template_mode=cf.TEM)
admin.add_view(ModelView(Servers, db.session))
admin.add_view(ModelView(Users, db.session))
admin.add_view(ModelView(Access, db.session))
admin.add_view(ModelView(Bastion, db.session))


if __name__ == '__main__':
    db.create_all()
    app.run(debug = cf.DEBUG, host=cf.SERVER, port = cf.PRTO, threaded=True)