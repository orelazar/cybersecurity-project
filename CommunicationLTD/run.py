from flask_migrate import Migrate
from app import create_app, db
import ssl


class AppConfig(object):
    DEBUG = True

    # Security
    SESSION_COOKIE_HTTPONLY  = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 3600
    SECRET_KEY = 'HIT_S#perS3crEtPa$$04D'

    # MSSQL database
#     SQLALCHEMY_DATABASE_URI = 'mssql+pymssql://hit:Aa123456@communicationltd.database.communicationltd'
    
    # Local MSSQL database
    SQLALCHEMY_DATABASE_URI = 'mssql+pymssql://sa:Aa123456@localhost:1433/communicationltd'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False


app_config = AppConfig
app = create_app(app_config) 
Migrate(app, db)

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('localhost.crt', 'localhost.key')

if __name__ == '__main__':
    app.run(host='localhost',debug=True, ssl_context=context)
    
