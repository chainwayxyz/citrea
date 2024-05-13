from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.cors import CORSMiddleware
from psycopg_pool import AsyncConnectionPool

from config import CONFIG
from routers import batch

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    def get_conn_str():
        return f"""
        host={CONFIG.db_host}
        port={CONFIG.db_port}
        user={CONFIG.db_user}
        password={CONFIG.db_password}
        dbname={CONFIG.db_name}
        """

    # Until yield executes before startup
    app.async_pool = AsyncConnectionPool(conninfo=get_conn_str())
    yield

    # Below here executes before shutdown
    await app.async_pool.close()


app = FastAPI(lifespan=lifespan)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

# should be settable by config
origins = [
    CONFIG.allowed_hosts
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def configure():
    configure_routing()


def configure_routing():
    app.include_router(batch.router)


@app.get("/")
async def root():
    return {"msg": "Citrea batch explorer"}


configure()
