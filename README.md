# SafeVault Secure MVC Sample

SafeVault is an ASP.NET Core MVC sample focused on secure coding practices for sensitive data workflows.

## What This Project Demonstrates

- Input sanitization and validation for form submissions
- Parameterized SQL queries with SQLite
- Secure password hashing with BCrypt
- Role-based access control (Admin/User)
- Route protection with cookie authentication
- Security-focused tests for SQL injection, XSS, invalid auth, and authorization

## Tech Stack

- .NET 10 MVC
- SQLite (`Microsoft.Data.Sqlite`)
- BCrypt (`BCrypt.Net-Next`)
- NUnit for tests

## Project Structure

- `Controllers/`
  - `HomeController`: secure form submission path
  - `AccountController`: register/login/logout/access denied
  - `AdminController`: admin-only role assignment
  - `VaultController`: authenticated role-protected feature
- `Data/`
  - `DatabaseInitializer`: schema creation/upgrades
  - `UserRepository`: parameterized queries
- `Security/`
  - `InputSanitizer`: username/email sanitization and HTML escaping
  - `AuthenticationService`: login/register/role assignment logic
  - `BcryptPasswordHasher`: password hash/verify implementation
- `SecureApp.Tests/`
  - security unit and integration tests

## Run Locally

1. Restore and build

```bash
dotnet restore
dotnet build
```

2. Start the app

```bash
dotnet run
```

3. Open the local URL printed in the console.

## Security Notes

- SQL statements use parameter placeholders (`@param`) instead of string concatenation.
- Username search escapes SQL LIKE wildcard characters before parameter binding.
- User inputs are sanitized before validation and persistence.
- Razor output is HTML-encoded by default; additional `EscapeForHtml` helper is available for defense in depth.
- Authentication uses BCrypt hashes; plaintext passwords are never stored.

## Role Model

- First registered account is assigned `Admin` automatically.
- Later registrations default to `User`.
- Admin users can assign roles through the Admin page.
- Access restrictions:
  - `/Admin` requires `Admin`
  - `/Vault` requires authenticated `Admin` or `User`
  - `/Home/Privacy` requires authentication

## Run Tests

```bash
dotnet test SecureApp.Tests/SecureApp.Tests.csproj
```

The suite includes:

- SQL injection simulation tests
- XSS payload tests through model and controller paths
- Invalid login attempt tests
- Unauthorized and role-based route access tests
- Integration tests for access control behavior

## Suggested Next Steps

- Add account lockout/rate limiting for brute-force protection.
- Add structured security logging and audit trails for role changes.
- Move connection strings and secrets to environment variables or secret stores.
