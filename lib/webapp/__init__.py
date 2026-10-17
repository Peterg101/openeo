"""OpenEO web application (FastAPI) support package.

Importing this package must stay cheap and dependency free: the pure helper
modules in here (passwords, csrf, secret_keys ...) are also used by the root
first-boot step and by the portal, neither of which has FastAPI loaded.
"""
