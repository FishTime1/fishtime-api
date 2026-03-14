from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str
    JWT_SECRET: str
    ADMIN_KEY: str = "4e1ace7667"
    ADMIN_WEB_USERNAME: str = "fishtimeadmincan"
    ADMIN_WEB_PASSWORD: str = "4e1ace7667"
    DEVICE_LIMIT: int = 3
    TOKEN_EXPIRE_MINUTES: int = 1440
    ADMIN_TOKEN_EXPIRE_MINUTES: int = 10080


settings = Settings()
