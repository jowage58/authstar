import logging
import secrets
from pathlib import Path

import pydantic_settings

__version__ = "0.0.1"

PACKAGE_ROOT = Path(__file__).parent
PROJECT_ROOT = PACKAGE_ROOT.parent


class SharedSettings(pydantic_settings.BaseSettings):
    model_config = {"env_file": PROJECT_ROOT / ".env", "frozen": True}  # noqa: RUF012


class LogSettings(SharedSettings, env_prefix="LOG_"):
    level_app: str = "INFO"
    level_root: str = "INFO"
    level_uvicorn: str = "INFO"


log = LogSettings()

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s:%(funcName)s %(message)s"
)
logging.getLogger().setLevel(log.level_root)
logging.getLogger("uvicorn").setLevel(log.level_uvicorn)

logger = logging.getLogger("example")
logger.setLevel(log.level_app)


class APISettings(SharedSettings, env_prefix="API_"):
    version: str = __version__
    debug: bool = False
    secret_key: str = secrets.token_urlsafe(32)
    auth_token_cache_url: str = "memory://"
    auth_token_cache_ttl: float = 180.0


api = APISettings()
