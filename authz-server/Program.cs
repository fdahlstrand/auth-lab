using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

static string GenerateToken()
{
    var secret = "foobar1234foobar1234";
    var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret));
    var descriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] {
            new Claim("role", "admin"),
            new Claim("users", "list"),
            new Claim("users", "add"),
        }),
        Expires = DateTime.UtcNow.AddHours(1),
        Issuer = "https://localhost:7273",
        Audience = "<not implemented>",
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
    };
    var handler = new JwtSecurityTokenHandler();
    var token = handler.CreateToken(descriptor);
    return handler.WriteToken(token);
}


app.MapGet("/oauth2/callback", async
([FromQuery(Name = "code")] string code,
 [FromQuery(Name = "state")] string state)
=>
{
    app.Logger.LogInformation("Code: {code}", code);
    app.Logger.LogInformation("State: {state}", state);

    // Exchange code for token
    var handler = new HttpClientHandler
    {
        ClientCertificateOptions = ClientCertificateOption.Manual,
        ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErrors) => true
    };
    var client = new HttpClient(handler);
    var content = new FormUrlEncodedContent(new[]
    {
        new KeyValuePair<string,string>("grant_type", "authorization_code"),
        new KeyValuePair<string,string>("code", code),
        new KeyValuePair<string,string>("redirect_uri", "https://localhost:7273/oauth2/callback"),
        new KeyValuePair<string,string>("client_id", "https://localhost:7273"),
        new KeyValuePair<string,string>("client_secret", "verysecretstring"),
    });
    var response = await client.PostAsync("https://localhost:7278/oauth/token", content);
    app.Logger.LogInformation("Token Response Code: {res}", response.StatusCode);

    var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();

    app.Logger.LogInformation("ID Token {token}", tokenResponse.AccessToken);
    string secret = "yadayada1234yadayada1234";
    var key = Encoding.ASCII.GetBytes(secret);
    var validations = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
    var tokenHandler = new JwtSecurityTokenHandler();
    var principal = tokenHandler.ValidateToken(tokenResponse.AccessToken, validations, out var idToken);
    foreach (var claim in principal.Claims)
    {
        app.Logger.LogInformation("Claim {key} = {value}", claim.Type, claim.Value);
    }

    var token = GenerateToken();

    var builder = new UriBuilder("https://oauth.pstmn.io/v1/browser-callback");
    builder.Fragment = $"access_token={token}&token_type=Bearer&expires_in=3600&scope={"TBD"}&state={"state"}";

    app.Logger.LogInformation("Redirecting {uri}", builder.ToString());

    return Results.Redirect(builder.ToString());
});

app.MapGet(
    "/oauth2/authorize",
    ([FromQuery(Name = "client_id")] string clientId,
     [FromQuery(Name = "response_type")] string responseType,
     [FromQuery(Name = "scope")] string scope,
     [FromQuery(Name = "state")] string state,
     [FromQuery(Name = "redirect_uri")] string redirectUri)
    =>
    {
        app.Logger.LogInformation("Client: {client_id}", clientId);
        app.Logger.LogInformation("Response Type: {response}", responseType);
        app.Logger.LogInformation("Scope: {scope}", scope);
        app.Logger.LogInformation("State: {state}", state);
        app.Logger.LogInformation("Redirect: {redirect_uri}", redirectUri);

        // TODO: Verify authorization request

        // Request id token
        var builder = new UriBuilder("https://localhost:7278/oauth/authorize")
        {
            Query = $"response_type=code&" +
                    $"client_id={WebUtility.UrlEncode("https://localhost:7273")}&" +
                    $"state=42&" +
                    $"scope=openid&" +
                    $"redirect_uri={WebUtility.UrlEncode("https://localhost:7273/oauth2/callback")}"
        };


        app.Logger.LogInformation("Redirecting {uri}", builder.ToString());
        return Results.Redirect(builder.ToString());
    });

app.Run();

public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
}
