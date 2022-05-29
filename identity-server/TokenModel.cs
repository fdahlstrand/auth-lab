using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace identity_server.Pages;

[ApiController]
[Route("oauth/token")]
public class TokenModel : ControllerBase
{
    private readonly ILogger<TokenModel> _logger;

    private readonly TokenService _tokenService;

    public TokenModel(
        ILogger<TokenModel> logger,
        TokenService tokenService)
    {
        _logger = logger;
        _tokenService = tokenService;
    }

    [HttpPost]
    [IgnoreAntiforgeryToken]
    public IActionResult OnPost(
        [FromForm] TokenRequest request
    )
    {
        _logger.LogInformation("Grant: {grant}", request.GrantType);
        _logger.LogInformation("Client ID: {client}", request.ClientId);
        _logger.LogInformation("Code: {code}", request.Code);
        _logger.LogInformation("Redirect URI: {uri}", request.RedirectUri);
        _logger.LogInformation("Secret: {uri}", request.Secret);

        // TODO: Validate information

        var token = _tokenService.GetToken(request.Code);

        _logger.LogInformation("Token: {t}", token);

        return new JsonResult(new TokenResponse
        {
            AccessToken = token,
            TokenType = "Bearer",
            ExpiresIn = 3600
        });
    }
}

public class TokenRequest
{
    [FromForm(Name = "grant_type")]
    public string? GrantType { get; set; }

    [FromForm(Name = "code")]
    public string? Code { get; set; }

    [FromForm(Name = "redirect_uri")]
    public string? RedirectUri { get; set; }

    [FromForm(Name = "client_id")]
    public string? ClientId { get; set; }

    [FromForm(Name = "client_secret")]
    public string? Secret { get; set; }
}

public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
}