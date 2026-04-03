using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureApp.Models;
using SecureApp.Security;

namespace SecureApp.Controllers;

[Authorize(Roles = AppRoles.Admin)]
public class AdminController(IAuthenticationService authenticationService, IInputSanitizer inputSanitizer) : Controller
{
    public IActionResult Index()
    {
        return View(new AssignRoleInputModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssignRole(AssignRoleInputModel model, CancellationToken cancellationToken)
    {
        var originalUsername = model.Username;
        model.Username = inputSanitizer.SanitizeUsername(model.Username);

        if (!string.Equals(originalUsername, model.Username, StringComparison.Ordinal))
        {
            ModelState.AddModelError(string.Empty, "Input contains unsupported or potentially harmful characters.");
        }

        if (!ModelState.IsValid)
        {
            return View("Index", model);
        }

        try
        {
            await authenticationService.AssignRoleAsync(model.Username, model.Role, cancellationToken);
            var safeUsername = inputSanitizer.EscapeForHtml(model.Username);
            ViewData["SuccessMessage"] = $"Assigned role {model.Role} to {safeUsername}.";
            return View("Index", new AssignRoleInputModel());
        }
        catch (InvalidOperationException ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
            return View("Index", model);
        }
    }
}