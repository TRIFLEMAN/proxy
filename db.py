import pymysql


def get_db():

    return pymysql.connect(
        host="10.101.1.211",
        user="password",
        password="password",
        database="logcollector",
        cursorclass=pymysql.cursors.DictCursor
    )
