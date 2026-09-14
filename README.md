## About

Mechano Auth Service is a dedicated authentication and authorization service for the Mechano vehicle maintenance platform.

It handles user registration, login, JWT access tokens, refresh tokens, logout, and user roles. Authentication data is stored in a dedicated `auth` schema, while the main Mechano backend manages user profiles and business data in the `public` schema.

New registrations are assigned the standard `ROLE_USER` role, while additional roles such as `ROLE_SHOP_OWNER` and `ROLE_ADMIN` can be managed separately.

### Main Features

- User registration
- User login
- JWT access token generation
- Refresh token rotation
- Logout and refresh token revocation
- Role-based authorization
- Support for `ROLE_USER`, `ROLE_SHOP_OWNER`, and `ROLE_ADMIN`
- Automatic creation of a corresponding Mechano user profile
- PostgreSQL database
- Liquibase database migrations
- Swagger / OpenAPI documentation
- Spring Security integration
