#!/usr/bin/env python3
__author__ = 'Luis Geronimo'
# APP principal
from app import app, cf, db, login_manager

# Packages log
import logging
from datetime import datetime, timedelta

# Flask admin
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView

# Models
from app.models import Servers, Users, Access, Bastion, AdminView, Policy, UGPolicies, Groups, UGRelation, GSRelation

# Flask Login
from flask_login import current_user, logout_user

# Logs
LOG_FILENAME = datetime.now().strftime(cf.LOG_DIR)
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(filename=LOG_FILENAME, level=cf.LOG_LEVEL)
logging.info('Comenzando la aplicacion...')

############################## Admin ###################################
@login_manager.user_loader
def load_user(id):
    return Users.query.get(id)

# Definir una función para verificar si el usuario está autenticado
def is_user_authenticated():
    return current_user.is_authenticated

# Crear una clase personalizada para el administrador que herede de AdminIndexView
class CustomAdminIndexView(AdminIndexView):
    # Sobrescribir el método is_accessible para verificar si el usuario está autenticado
    def is_accessible(self):
        return is_user_authenticated()

# Crear una clase personalizada para las vistas de modelos que herede de ModelView
class CustomModelView(ModelView):
    # Sobrescribir el método is_accessible para verificar si el usuario está autenticado
    def is_accessible(self):
        return is_user_authenticated()

# Variable para almacenar el tiempo de inactividad permitido (en segundos)
TIEMPO_INACTIVIDAD = 900  # 15 minutos

# Función para verificar la actividad del usuario y cerrar sesión si es necesario
def verificar_inactividad():
    ultimo_acceso = app.config.get('ULTIMO_ACCESO')
    if ultimo_acceso is not None and datetime.now() > ultimo_acceso + timedelta(seconds=TIEMPO_INACTIVIDAD):
        logout_user()
        # También puedes agregar cualquier otra lógica adicional que desees realizar al cerrar la sesión del usuario

# Función para actualizar el tiempo de actividad del usuario
def actualizar_actividad():
    app.config['ULTIMO_ACCESO'] = datetime.now()

# Lógica para actualizar la actividad del usuario en cada solicitud
@app.before_request
def before_request():
    actualizar_actividad()

admin = Admin(app, url=cf.LINK, index_view=CustomAdminIndexView(), name=cf.NAMEAPP, template_mode=cf.TEM)
admin.add_view(CustomModelView(Servers, db.session))
admin.add_view(CustomModelView(Users, db.session))
admin.add_view(CustomModelView(Groups, db.session))
admin.add_view(CustomModelView(UGPolicies, db.session))
admin.add_view(CustomModelView(UGRelation, db.session))
admin.add_view(CustomModelView(GSRelation, db.session))
admin.add_view(CustomModelView(Policy, db.session))
admin.add_view(CustomModelView(Access, db.session))
admin.add_view(CustomModelView(Bastion, db.session))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=cf.DEBUG, host=cf.SERVER, port=cf.PRTO, threaded=True)