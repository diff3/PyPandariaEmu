from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from database.AuthModel import Base, Account, AccountBanned, Realmlist  # Importera modellerna

import yaml

with open("etc/config.yaml", 'r') as file:
    config = yaml.safe_load(file)

# Anslutningar
SERVER_URL = f"mysql+pymysql://{config["database"]["user"]}:{config["database"]["password"]}@{config["database"]["host"]}:{config["database"]["port"]}"
DATABASE_URL = f"{SERVER_URL}/{config["database"]['db']}?charset={config["database"]["charset"]}"

# Skapa en session
SessionLocal = sessionmaker(autocommit=False, autoflush=False)


def database_exists():
    """Kontrollera om databasen existerar."""
    engine = create_engine(SERVER_URL, echo=False)
    with engine.connect() as connection:
        result = connection.execute(text(f"SHOW DATABASES LIKE '{config["database"]['db']}'"))
        return result.fetchone() is not None


def tables_exist(engine):
    """Kontrollera om tabellerna finns."""
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    required_tables = [Account.__tablename__, AccountBanned.__tablename__, Realmlist.__tablename__]
    return all(table in tables for table in required_tables)


def create_database():
    """Skapa databasen om den inte finns."""
    engine = create_engine(SERVER_URL, echo=False)
    with engine.connect() as connection:
        connection.execute(text(f"CREATE DATABASE IF NOT EXISTS {config["database"]['db']}"))
        print(f"Databasen '{config["database"]['db']}' skapades eller finns redan.")


def create_tables():
    """Skapa tabellerna om de inte finns."""
    engine = create_engine(DATABASE_URL, echo=True)
    if not tables_exist(engine):
        Base.metadata.create_all(bind=engine)
        print("Tabellerna har skapats.")
    else:
        print("Tabellerna finns redan.")


if __name__ == "__main__":
    # Kontrollera om databasen finns, annars skapa den
    if not database_exists():
        create_database()

    # Kontrollera och skapa tabellerna
    create_tables()

