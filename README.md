## About

Mechano Auth Service is a standalone authentication service for the Mechano platform.

It is responsible for user registration, login, JWT access token generation, refresh token handling, logout, and role management. The service stores authentication-related data separately from the main Mechano business domain while using the same PostgreSQL database with a dedicated schema.

The service is built with Java 21, Spring Boot, Spring Security, Spring Data JPA, PostgreSQL, Liquibase, and OpenAPI. It supports role-based authentication with `ROLE_USER`, `ROLE_SHOP_OWNER`, and `ROLE_ADMIN`, short-lived JWT access tokens, and revocable refresh tokens.
