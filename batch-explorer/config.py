from pydantic_settings import BaseSettings
from decouple import config


class Settings(BaseSettings):
    """Server config settings"""

    # name of app
    app_name: str = "Citrea API"

    # Environment type
    env: str = config("ENV", default="test")

    # Server settings
    l2_rpc_url: str = config("L2_RPC_URL", default="http://0.0.0.0:12345")
    blockscout_url: str = config("BLOCKSCOUT_URL", default="http://127.0.0.1")
    mempool_space_url: str = config(
        "MEMPOOL_SPACE_URL", default="https://mempool.space"
    )

    # DB settings
    db_host: str = config("DB_HOST", default="localhost")
    db_port: int = config("DB_PORT", default=5432)
    db_user: str = config("DB_USER", default="postgres")
    db_password: str = config("DB_PASSWORD", default="postgres")
    db_name: str = config("DB_NAME", default="postgres")

    allowed_hosts: list = ["*"]

    class Config:
        env_file = ".env"
        orm_mode = True


CONFIG = Settings()
