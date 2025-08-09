# SpringAuthServer

A Spring Boot **Authorization Server** using **Spring Authorization Server** package with **MySQL**.  
Supports:
- **Basic Authentication** – `/login` with username & password.
- **Authorization Code Flow** – `/oauth2/authorize` → get code → `/oauth2/token`.
- **Client Credentials Flow** – `/oauth2/token` with `grant_type=client_credentials`.

**Tech Stack:** Java 17+, Spring Boot 3+, Spring Security, OAuth2, MySQL.
