using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace SecureApp.Security;

public interface IInputSanitizer
{
    string SanitizeUsername(string input);
    string SanitizeEmail(string input);
    string EscapeForHtml(string input);
}

public partial class InputSanitizer : IInputSanitizer
{
    public string SanitizeUsername(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var trimmed = input.Trim();
        var builder = new StringBuilder(trimmed.Length);

        // Username uses a strict allowlist to avoid script/query control characters.
        foreach (var c in trimmed)
        {
            if (char.IsLetterOrDigit(c) || c is '_' or '.' or '-')
            {
                builder.Append(c);
            }
        }

        return builder.ToString();
    }

    public string SanitizeEmail(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var trimmed = input.Trim();
        var withoutControlChars = ControlCharsRegex().Replace(trimmed, string.Empty);

        return withoutControlChars
            .Replace("<", string.Empty, StringComparison.Ordinal)
            .Replace(">", string.Empty, StringComparison.Ordinal)
            .Replace("\"", string.Empty, StringComparison.Ordinal)
            .Replace("'", string.Empty, StringComparison.Ordinal)
            .Replace(";", string.Empty, StringComparison.Ordinal);
    }

    public string EscapeForHtml(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        // Defense-in-depth helper for any value that might be rendered as text in views.
        return HtmlEncoder.Default.Encode(input);
    }

    [GeneratedRegex(@"[\u0000-\u001F\u007F]")]
    private static partial Regex ControlCharsRegex();
}