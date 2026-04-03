using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureApp.Security;

namespace SecureApp.Tests.Tests;

[TestFixture]
public class AuthorizationIntegrationTests
{
    [Test]
    public async Task UnauthenticatedUser_IsRedirectedFromProtectedRoute()
    {
        await using var factory = new SecureAppWebApplicationFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var response = await client.GetAsync("/Home/Privacy");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location?.ToString(), Does.Contain("/Account/Login"));
    }

    [Test]
    public async Task UserRole_IsDeniedAdminRoute()
    {
        await using var factory = new SecureAppWebApplicationFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("X-Test-User", "member");
        client.DefaultRequestHeaders.Add("X-Test-Role", AppRoles.User);

        var response = await client.GetAsync("/Admin");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location?.ToString(), Does.Contain("/Account/AccessDenied"));
    }

    [Test]
    public async Task AdminRole_CanAccessAdminRoute()
    {
        await using var factory = new SecureAppWebApplicationFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("X-Test-User", "admin");
        client.DefaultRequestHeaders.Add("X-Test-Role", AppRoles.Admin);

        var response = await client.GetAsync("/Admin");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task UserRole_CanAccessVaultRoute()
    {
        await using var factory = new SecureAppWebApplicationFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("X-Test-User", "member");
        client.DefaultRequestHeaders.Add("X-Test-Role", AppRoles.User);

        var response = await client.GetAsync("/Vault");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    private sealed class SecureAppWebApplicationFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.AddAuthentication(options =>
                    {
                        options.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
                        options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                        options.DefaultForbidScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    })
                    .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
            });
        }
    }

    private sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public const string SchemeName = "TestAuth";

        public TestAuthHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("X-Test-User", out var username) ||
                string.IsNullOrWhiteSpace(username))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var role = Request.Headers.TryGetValue("X-Test-Role", out var roleValue) && !string.IsNullOrWhiteSpace(roleValue)
                ? roleValue.ToString()
                : AppRoles.User;

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username.ToString()),
                new Claim(ClaimTypes.Role, role)
            };

            var identity = new ClaimsIdentity(claims, SchemeName);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, SchemeName);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }
}
