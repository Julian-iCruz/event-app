# Incializacion ENV

```bash
virutalenv env
```

```bash
source ./env/bin/activate
```

```bash
pip install -r requirements.txt
```

# Postgres SQL

1. sudo apt install postgresql postgresql-contib
2. netstat -plnt (Revisar si esta ejecutandose en el puerto 5432)
    2.1 sudo service postgresql restart (En caso de que no este ejecutandoes)
3. sudo su - postgres psql
4. sudo -u postgres createuser --createdb --pwrompt <user_name> 
(Creacion de usuario y pass)
    4.1 CREATE USER nksistemas PASSWORD 'TU_PASSWORD'; (En caso de que no lo deje con el anteriro comando sse ingresa a postgres y sse ejecuta)
5. sudo -u postgres createdb --owner=<user_name> <db_name>  (Crear base de datos)
6. psql --host localhost --user main (entrar a la base de datos)

