import os

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base, sessionmaker


def build_database_url():
    explicit = os.getenv("DATABASE_URL", "").strip()
    if explicit:
        return explicit

    host = os.getenv("DB_HOST", "").strip()
    if host:
        return URL.create(
            drivername="postgresql+psycopg",
            username=os.getenv("DB_USER", "patchmgr"),
            password=os.getenv("DB_PASSWORD", ""),
            host=host,
            port=int(os.getenv("DB_PORT", "5432")),
            database=os.getenv("DB_NAME", "patchmgr"),
        )

    return "sqlite:///./patchmgr.db"


DATABASE_URL = build_database_url()
is_sqlite = (
    DATABASE_URL.drivername.startswith("sqlite")
    if isinstance(DATABASE_URL, URL)
    else str(DATABASE_URL).startswith("sqlite")
)
connect_args = {"check_same_thread": False} if is_sqlite else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def database_url_string() -> str:
    if isinstance(DATABASE_URL, URL):
        return DATABASE_URL.render_as_string(hide_password=False)
    return str(DATABASE_URL)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
