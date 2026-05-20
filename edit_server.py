import sys

with open("app/main.py", "r") as f:
    text = f.read()

text = text.replace(
    'API_KEY = os.getenv("OPT_SERVER_API_KEY", "default-secure-key-change-me")',
    '''ADMIN_TOKEN = os.getenv("OPT_ADMIN_TOKEN", "default-admin-token")
API_KEY = os.getenv("OPT_SERVER_API_KEY", "default-secure-key-change-me")

# Alternatively, if mounted via config file from sentinel
if os.path.exists("/config/admin_token.txt"):
    with open("/config/admin_token.txt", "r") as f:
        ADMIN_TOKEN = f.read().strip()
'''
)

with open("app/main.py", "w") as f:
    f.write(text)
