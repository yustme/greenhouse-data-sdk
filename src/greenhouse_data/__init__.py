"""Install with pip from GitHub, then use Greenhouse's managed environment variables.

    from greenhouse_data import CorporateClient
    with CorporateClient.from_env() as data:
        rows = data.read("teste", "test_data", limit=25)

All authorization remains server-side; this client cannot grant package access.
"""
from .client import CorporateClient, CorporateError
from .config import ClientSettings

__all__ = ["CorporateClient", "CorporateError", "ClientSettings"]
