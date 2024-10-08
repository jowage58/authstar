import logging
import secrets
from pathlib import Path

from starlette.config import Config
from starlette.datastructures import Secret

__version__ = "0.0.1"

PACKAGE_ROOT = Path(__file__).parent
PROJECT_ROOT = PACKAGE_ROOT.parent

_cfg = Config(env_file=PROJECT_ROOT / ".env")

VERSION = _cfg("API_VERSION", default=__version__)
DEBUG = _cfg("API_DEBUG", cast=bool, default=False)
SECRET_KEY = _cfg("API_SECRET_KEY", cast=Secret, default=secrets.token_urlsafe(32))
AUTH_TOKEN_CACHE_URL = _cfg("API_AUTH_TOKEN_CACHE_URL", default="memory://")
AUTH_TOKEN_CACHE_TTL = _cfg("API_AUTH_TOKEN_CACHE_TTL", cast=float, default=180.0)

LOG_LEVEL_ROOT = _cfg("LOG_LEVEL_ROOT", default="INFO")
LOG_LEVEL_UVICORN = _cfg("LOG_LEVEL_UVICORN", default="INFO")
LOG_LEVEL_APP = _cfg("LOG_LEVEL_APP", default="INFO")

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s:%(funcName)s %(message)s",
    level=LOG_LEVEL_ROOT,
)
logging.getLogger("uvicorn").setLevel(LOG_LEVEL_UVICORN)

logger = logging.getLogger("example")
logger.setLevel(LOG_LEVEL_APP)
