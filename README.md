# Rustbase

A base template to build web application with Rust.

![image](https://github.com/huytd/rustbase/assets/613943/9d4158b8-2fc9-4590-a520-b2e005d7bcdd)

Tech stack:
- SuperTokens Core (for authentication)
- Postgres
- Rust (API backend)
- Next.js (UI)

## How to develop (locally)

Start Docker containers with:

```shell
$ docker compose up
```

This will start the Postgres database and SuperTokens Core in the docker container.

Next, start the Frontend:

```shell
$ cd frontend && npm run dev
```

This will start a Next.js application, with the authentication API and UI pre-installed.

Finally, start the Backend:

```shell
$ cd backend && cargo run 
```

This will start the Rust backend API, the Frontend can call this API via `/api/v1` endpoint.
