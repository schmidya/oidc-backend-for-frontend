# OAuth2/OIDC Backend-for-Frontend

The backend-for-frontend (BFF) pattern is the current state of the art for securing API calls from SPA frontends which might be exposed to malicious JavaScript via cross-site-scripting (XSS) or compromised open source dependencies.

The BFF has two core functions:
1. It handles the Authorization Code flow with PKCE instead of the frontend. Effectively, the BFF and the browser (but crucially: not the JavaScript frontend) act as a distributed OAuth2 client which performs that flow in  the standard way.
2. It acts as a reverse proxy for API calls: The browser stores a HTTP-only session cookie for the BFF. This enables the BFF to insert the necessary authorization headers with JWT bearer tokens from the auth server. The API can then authorize requests based on these bearer tokens as usual.

While point 1 is the more interesting technical feature, it is usually point 2 that represents the bigger implementation challenge: Builing an efficient reverse proxy is tricky. Because of this, implementing a BFF is easiest in a language that has a decent library for reverse proxy functionality. This repository uses Go with its built-in reverse proxy from `httputil`.

## Setup

Start the Keycloak auth server via `docker compose up`

Confgure the Keycloak realm by logging in to the console at `localhost:8181`:
- Create realm `test`
- Create clients `bff` and `backend`. The bff client should be confidential. Add the client secret to the `.env`. The `backend` client is used to represent the backend API at the OAuth2 level: It will be the audience for the access token. 
- Set the URLs in the `bff` client so that the BFF can perform the authorization code flow: Root URL: `http://localhost:8000`, valid redirect URL: `/auth/callback`.
- Create the scope `api`. This scope will authorize requests to the API backend, therefore this scope must be added to the token `scope` claim. Then, add a mapper to this scope which will add the `backend` to the audience claim whenever this scope is requested.
- create a user and set their password. In the realm settings, set the email to an optional field so keycloak doesn't ask for it.

Create the `.env` file, and add the variables:
```
BACKEND_URL=http://localhost:8000
AUTH_URL=http://localhost:8181/realms/test/protocol/openid-connect/
CLIENT_ID=<client id of the bff>
CLIENT_SECRET=<client secret of the bff>
```

Start the fastAPI backend: Create a python venv and install the requirements. Then start the dev server: `fastapi dev api.py --port 8080`

Start the BFF using the `air` command for automatic reloading. Note that the frontend is served via the BFF using Go's built-in file server. It can be accessed at `http://localhost:8000`.