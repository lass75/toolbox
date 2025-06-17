import psycopg2

def get_connection():
    return psycopg2.connect(
        dbname="toolbox",
        user="admin",
        password="admin",
        host="db"
    )
