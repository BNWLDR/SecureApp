using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureApp.Data;
using SecureApp.Models;
using SecureApp.Security;

namespace SecureApp.Controllers;

public class HomeController(IUserRepository userRepository, IInputSanitizer inputSanitizer) : Controller
{
    public IActionResult Index()
    {
        return View(new UserInputModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Submit(UserInputModel model, CancellationToken cancellationToken)
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
            return View("Index", model);
        }

        await userRepository.CreateUserAsync(model.Username, model.Email, cancellationToken);
        ViewData["SuccessMessage"] = "Data was submitted securely.";
        return View("Index", new UserInputModel());
    }

    [Authorize]
    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
