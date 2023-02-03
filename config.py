from decouple import config

user = config('POSTGRES_USER')
password = config('POSTGRES_PASS')
host = config('POSTGRES_HOST')
port = config('POSTGRES_PORT')
database = config('POSTGRES_DB')

DATABASE_CONNECTION_URI = f'postgresql://{user}:{password}@{host}:{port}/{database}'