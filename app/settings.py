from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str
    JWT_SECRET: str
    ADMIN_KEY: str = "4e1ace7667"
    DEVICE_LIMIT: int = 3
    TOKEN_EXPIRE_MINUTES: int = 1440


settings = Settings()