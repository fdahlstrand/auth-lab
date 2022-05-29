using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.Tokens;

namespace identity_server.Pages;

[IgnoreAntiforgeryToken(Order = 1001)]
public class AuthorizeModel : PageModel
{
    [BindProperty]
    public Credential Credential { get; set; }

    private readonly ILogger<AuthorizeModel> _logger;

    private readonly TokenService _tokenService;

    public AuthorizeModel(
        ILogger<AuthorizeModel> logger,
        TokenService tokenService)
    {
        Credential = new Credential();
        _logger = logger;
        _tokenService = tokenService;
    }

    public IActionResult OnGet(
        [FromQuery(Name = "response_type")] string responseType,
        [FromQuery(Name = "client_id")] string clientId,
        [FromQuery(Name = "redirect_uri")] string? redirectUri,
        [FromQuery(Name = "scope")] string scope,
        [FromQuery(Name = "state")] string state)
    {
        if (redirectUri == null)
        {
            redirectUri = HttpContext.Session.GetString("redirect_uri");
        }

        // TODO: Add a lot of checking...

        _logger.LogInformation("Response Type = {responseType}", responseType);
        _logger.LogInformation("Client ID = {clientId}", clientId);
        _logger.LogInformation("Redirect URI = {redirectUri}", redirectUri);
        _logger.LogInformation("Scope = {scope}", scope);
        _logger.LogInformation("State = {state}", state);

        if (User.Identity != null && User.Identity.IsAuthenticated)
        {
            _logger.LogInformation("Already authenticated {user}", User.Identity.Name);

            if (redirectUri != null)
            {
                var b = new UriBuilder(redirectUri);

                var code = _tokenService.GenerateCode(User.Identity);
                var xstate = "12345";

                b.Query = $"code={code}&state={xstate}";

                _logger.LogInformation("Reply: {uri}", b.ToString());

                return Redirect(b.ToString());
            }

            return RedirectToPage("/Index");
        }

        if (redirectUri != null)
        {
            HttpContext.Session.SetString("redirect_uri", redirectUri);
        }


        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid) return Page();

        if (Credential.Username == "joe" && Credential.Password == "password")
        {
            _logger.LogInformation("User: {username}", Credential.Username);
            var claims = new Claim[] {
                new Claim(JwtRegisteredClaimNames.Sub, "joe"),
                new Claim(ClaimTypes.Name, "joe"),
                new Claim(ClaimTypes.GivenName, "G.I. Joe"),
                new Claim(ClaimTypes.Email, "g.i.joe@example.com"),
                new Claim(ClaimTypes.Role, "admin"),
            };
            var identity = new ClaimsIdentity(claims, "AuthCookie");
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync("AuthCookie", principal);

            return RedirectToPage();
        }

        return Page();
    }
}

public class Credential
{
    public Credential()
    {
        Username = "";
        Password = "";
    }

    [Required]
    public string Username { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

}
