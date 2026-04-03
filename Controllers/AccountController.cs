using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using SecureApp.Models;
using SecureApp.Security;

namespace SecureApp.Controllers;

public class AccountController(SecureApp.Security.IAuthenticationService authenticationService, IInputSanitizer inputSanitizer) : Controller
{
    public IActionResult Register()
    {
        return View(new RegisterInputModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterInputModel model, CancellationToken cancellationToken)
    {
        var originalUsername = model.Username;
        var originalEmail = model.Email;

        model.Username = inputSanitizer.SanitizeUsername(model.Username);
        model.Email = inputSanitizer.SanitizeEmail(model.Email);

        if (!string.Equals(originalUsername, model.Username, StringComparison.Ordinal) ||
            !string.Equals(originalEmail, model.Email, StringComparison.Ordinal))
        {
            ModelState.AddModelError(string.Empty, "Input contains unsupported or potentially harmful characters.");
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {
            await authenticationService.RegisterAsync(model.Username, model.Email, model.Password, cancellationToken);
            TempData["SuccessMessage"] = "Registration successful. You can now sign in.";
            return RedirectToAction(nameof(Login));
        }
        catch (InvalidOperationException ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
            return View(model);
        }
    }

    public IActionResult Login()
    {
        return View(new LoginInputModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginInputModel model, CancellationToken cancellationToken)
    {
        var originalUsername = model.Username;
        model.Username = inputSanitizer.SanitizeUsername(model.Username);

        if (!string.Equals(originalUsername, model.Username, StringComparison.Ordinal))
        {
            ModelState.AddModelError(string.Empty, "Input contains unsupported or potentially harmful characters.");
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var authenticated = await authenticationService.AuthenticateAsync(model.Username, model.Password, cancellationToken);
        if (!authenticated)
        {
            ModelState.AddModelError(string.Empty, "Invalid username or password.");
            return View(model);
        }

        var role = await authenticationService.GetRoleForUserAsync(model.Username, cancellationToken) ?? AppRoles.User;
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, model.Username),
            new(ClaimTypes.Role, role)
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        ViewData["SuccessMessage"] = "Authentication successful.";
        return View(new LoginInputModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Login));
    }

    public IActionResult AccessDenied()
    {
        return View();
    }
}