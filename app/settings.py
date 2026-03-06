from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str
    JWT_SECRET: str
    ADMIN_KEY: str
    DEVICE_LIMIT: int = 3
    TOKEN_EXPIRE_MINUTES: int = 1440  # 24h

settings = Settings()