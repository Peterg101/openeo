"""Framework-free business logic of the web UI.

Services receive their collaborators in the constructor, never import
fastapi/starlette and never touch globalState. They raise the domain errors in
`errors` and return plain data; lib/webapp/app.py turns those into HTTP.
"""
