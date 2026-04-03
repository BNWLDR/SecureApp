using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureApp.Security;

namespace SecureApp.Controllers;

[Authorize(Roles = AppRoles.Admin + "," + AppRoles.User)]
public class VaultController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}