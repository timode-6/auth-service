# Auth Service

Handles authentication for the system: issues and validates JWTs, stores credentials.

Part of a five-service stack — see [`k8s`](https://github.com/timode-6/k8s) for how it's deployed alongside [`api-gateway`](https://github.com/timode-6/api-gateway), [`user-service`](https://github.com/timode-6/user-service), [`order-service`](https://github.com/timode-6/order-service), and [`payment-service`](https://github.com/timode-6/payment-service).

## Responsibilities

- Registers credentials (`POST /api/authentications/register`), called by the gateway as the second step of its registration saga, referencing the `userId` created just before in User Service.
- Verifies logins and issues JWTs.
- Owns its own PostgreSQL database, versioned with Liquibase.

## Stack

- Java 21, Spring Boot, Spring Security
- Spring Data JPA + Liquibase
- PostgreSQL
- JWT via `jjwt`
- Lombok, JaCoCo, SonarQube

## Running locally

```bash
./gradlew bootRun
```

or:

```bash
docker compose up --build
```

## Notes

- Needs `jwt-secret`, `gateway-internal-secret`, and DB credentials — provisioned as SealedSecrets in the `k8s` repo.
- Checks an `X-Internal-Secret` header on incoming requests, so it can't be reached by skipping the gateway.