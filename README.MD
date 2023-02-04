# Video

El video se encuentra disponible en [este link ](https://uniandes-my.sharepoint.com/:v:/g/personal/j_iguavita_uniandes_edu_co/EdosqjRdBaxCje9oNWsPZh4ByncuvZwcjjlmuhIs4lQVLw?e=VoDQul).

* Nombre: **Julian Andres Iguavita Cruz**
* Login Uniandes: **j.iguavita**

# Incialización ENV

Se crea en primera intancia el entorno vitual dentro de la EC2 de AWS.
```bash
virutalenv env
```
Una vez creado el entorno virutal se procede a su activación.
```bash
source ./env/bin/activate
```
En el archivo **requirements.txt** estan las librerias con sus respectivas versiones con las cuales la aplicación fue implementada.
```bash
pip install -r requirements.txt
```

# Postgres SQL

1. Se descarga Postgres en el servidor donde se ejecutara la aplicación.
```bash
sudo apt install postgresql postgresql-contib
```
2. Revisar si esta ejecutandose Postgres en el puerto 5432.
```bash
netstat -plnt
```
3. En caso de que no este ejecutandose se restaura el servicio.
```bash
sudo service postgresql restart
```
4. Para acceder a Postgres se hace uso de psql.
```bash
sudo su - postgres psql
```
5.  Se procede a crear un usuario, este comando tambien pide una contraseña para el usuario que se esta creando.
```bash
sudo -u postgres createuser --createdb --pwrompt <user_name>
```
6. Se crea la base de datos pasando el usuario y el nombre de la base de datos.
```bash
sudo -u postgres createdb --owner=<user_name> <db_name>
```
7. Una vez creada ya podemos acceder a la base de datos y queda lista para recibir datos de la aplicación de flask.
```bash
psql --host localhost --user main
```

# Ejecución aplicación

Antes de ejecutar la aplicación se debe crear un archivo **.env** el cual debe contener las variables de entorno.
```bash
POSTGRES_USER = user
POSTGRES_PASS = password
POSTGRES_HOST = localhost
POSTGRES_PORT = 5432
POSTGRES_DB = database_name
```

Para la ejecucion de la aplicación se hace uso de:
```bash
flask --app app run --host=0.0.0.0
```
Una vez la aplicación se encuentre ejecutando se puede apuntar a la direccion IP de la intancia en la que se este ejecutando la app que por defecto tiene como puesto de salida el 5000. **IP:5000/**