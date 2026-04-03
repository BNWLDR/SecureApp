using System.ComponentModel.DataAnnotations;
using SecureApp.Security;

namespace SecureApp.Models;

public class AssignRoleInputModel
{
    [Required]
    [StringLength(50, MinimumLength = 3)]
    [RegularExpression(@"^[a-zA-Z0-9_.-]+$", ErrorMessage = "Username can only contain letters, numbers, underscore, dot, and hyphen.")]
    public string Username { get; set; } = string.Empty;

    [Required]
    [RegularExpression(@"^(Admin|User)$", ErrorMessage = "Role must be Admin or User.")]
    public string Role { get; set; } = AppRoles.User;
}