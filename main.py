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
from app.models import Hosting, Domain, Users, Rols, Register, Master, Slaves, Acls, Forwards, AdminView

#logs
lev=cf.LOG_LEVEL
LOG_FILENAME = datetime.now().strftime(cf.LOG_DIR)
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(filename=LOG_FILENAME,level=logging.lev)
logging.info('Comenzando la aplicacion...')

############################## Admin ###################################
@login_manager.user_loader
def load_user(id):
    return Users.query.get(id)

#admin = Admin(app, url=cf.LINK, index_view=AdminView(), name=cf.NAMEAPP, template_mode=cf.TEM)
#admin.add_view(ModelView(Domain, db.session))
#admin.add_view(ModelView(Hosting, db.session))
#admin.add_view(ModelView(Users, db.session))
#admin.add_view(ModelView(Rols, db.session))
#admin.add_view(ModelView(Register, db.session))
#admin.add_view(ModelView(Master, db.session))
#admin.add_view(ModelView(Slaves, db.session))
#admin.add_view(ModelView(Acls, db.session))
#admin.add_view(ModelView(Forwards, db.session))

if __name__ == '__main__':
    db.create_all()
    app.run(debug = cf.DEBUG, host=cf.SERVER, port = cf.PTO, threaded=True)