import httpx
import json
import jwt
import dotenv
from urllib.parse import urljoin

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse


variables = dotenv.dotenv_values(".env")

app = FastAPI()



app.add_middleware(
    CORSMiddleware,
    allow_origins=['localhost:8000'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_keys(endpoint_url):
    response = httpx.get(endpoint_url)
    payload = json.loads(response.content)
    keys = {d['kid'] : jwt.PyJWK(d, algorithm="RS256") for d in payload['keys']}

    return keys


@app.middleware("http")
async def jwt_verification(request: Request, call_next) -> Response:
    
    auth_header = request.headers.get("Authorization")
    print(f"Found authorization header: {auth_header}")


    keys = load_keys(urljoin(variables['AUTH_URL'], "certs"))  

    if auth_header is not None and auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):]
        jwt_header = jwt.get_unverified_header(token)

        jwt_payload = jwt.decode(token, keys[jwt_header['kid']], audience='backend', verify=True)

        print(jwt_payload)
    else:
        return PlainTextResponse(status_code=401)

    return await call_next(request)



@app.get("/api/message")
def read_root():
    return PlainTextResponse("This message was sent by the backend!")

