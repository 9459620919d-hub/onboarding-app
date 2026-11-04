import serverless_wsgi
from app import app

# Netlify function handler
def handler(event, context):
    return serverless_wsgi.handle_request(app, event, context)