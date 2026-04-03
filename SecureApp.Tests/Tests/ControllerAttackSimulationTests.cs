using Microsoft.AspNetCore.Mvc;
using SecureApp.Controllers;
using SecureApp.Data;
using SecureApp.Models;
using SecureApp.Security;

namespace SecureApp.Tests.Tests;

[TestFixture]
public class ControllerAttackSimulationTests
{
    [Test]
    public async Task HomeSubmit_WithSqlInjectionPayload_BlocksRequest()
    {
        var fakeRepository = new FakeUserRepository();
        var controller = new HomeController(fakeRepository, new InputSanitizer());

        var model = new UserInputModel
        {
            Username = "attacker' OR 1=1 --",
            Email = "safe@example.com"
        };

        var result = await controller.Submit(model, CancellationToken.None);

        Assert.That(controller.ModelState.IsValid, Is.False);
        Assert.That(fakeRepository.CreateUserCallCount, Is.EqualTo(0));
        Assert.That(result, Is.TypeOf<ViewResult>());
    }

    [Test]
    public async Task HomeSubmit_WithXssPayload_BlocksRequest()
    {
        var fakeRepository = new FakeUserRepository();
        var controller = new HomeController(fakeRepository, new InputSanitizer());

        var model = new UserInputModel
        {
            Username = "<script>alert('xss')</script>",
            Email = "safe@example.com"
        };

        var result = await controller.Submit(model, CancellationToken.None);

        Assert.That(controller.ModelState.IsValid, Is.False);
        Assert.That(fakeRepository.CreateUserCallCount, Is.EqualTo(0));
        Assert.That(result, Is.TypeOf<ViewResult>());
    }

    [Test]
    public async Task AccountLogin_WithSqlInjectionPayload_BlocksAuthentication()
    {
        var fakeAuth = new FakeAuthenticationService();
        var controller = new AccountController(fakeAuth, new InputSanitizer());

        var model = new LoginInputModel
        {
            Username = "admin' UNION SELECT --",
            Password = "AnyPassword123"
        };

        var result = await controller.Login(model, CancellationToken.None);

        Assert.That(controller.ModelState.IsValid, Is.False);
        Assert.That(fakeAuth.AuthenticateCallCount, Is.EqualTo(0));
        Assert.That(result, Is.TypeOf<ViewResult>());
    }

    [Test]
    public async Task AccountLogin_WithXssPayload_BlocksAuthentication()
    {
        var fakeAuth = new FakeAuthenticationService();
        var controller = new AccountController(fakeAuth, new InputSanitizer());

        var model = new LoginInputModel
        {
            Username = "<img src=x onerror=alert(1)>",
            Password = "AnyPassword123"
        };

        var result = await controller.Login(model, CancellationToken.None);

        Assert.That(controller.ModelState.IsValid, Is.False);
        Assert.That(fakeAuth.AuthenticateCallCount, Is.EqualTo(0));
        Assert.That(result, Is.TypeOf<ViewResult>());
    }

    private sealed class FakeUserRepository : IUserRepository
    {
        public int CreateUserCallCount { get; private set; }

        public Task<int> CreateUserAsync(string username, string email, CancellationToken cancellationToken = default)
        {
            CreateUserCallCount++;
            return Task.FromResult(1);
        }

        public Task<int> CreateUserWithPasswordHashAsync(string username, string email, string passwordHash, string role, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<UserRecord?> GetUserByEmailAsync(string email, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<UserAuthRecord?> GetUserAuthByUsernameAsync(string username, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<IReadOnlyList<UserRecord>> SearchUsersByUsernameAsync(string searchTerm, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<int> CountUsersAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<string?> GetRoleByUsernameAsync(string username, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<int> UpdateUserRoleAsync(string username, string role, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
    }

    private sealed class FakeAuthenticationService : SecureApp.Security.IAuthenticationService
    {
        public int AuthenticateCallCount { get; private set; }

        public Task<bool> AuthenticateAsync(string username, string password, CancellationToken cancellationToken = default)
        {
            AuthenticateCallCount++;
            return Task.FromResult(false);
        }

        public Task RegisterAsync(string username, string email, string password, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<string?> GetRoleForUserAsync(string username, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task AssignRoleAsync(string username, string role, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
    }
}
