using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();


void DecodeToken(string token, ILogger logger)
{
    string secret = "foobar1234foobar1234";
    var key = System.Text.Encoding.ASCII.GetBytes(secret);
    var validations = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
    var tokenHandler = new JwtSecurityTokenHandler();
    var principal = tokenHandler.ValidateToken(token, validations, out var idToken);
    foreach (var claim in principal.Claims)
    {
        logger.LogInformation("Claim {key} = {value}", claim.Type, claim.Value);
    }
}

app.MapGet("/", (HttpRequest request) =>
{
    var token = request.Headers.Authorization.ToString().Split(' ')[1];
    app.Logger.LogInformation("Authorization Token: {token}", token);
    DecodeToken(token, app.Logger);
    return "Hello World";
});

app.Run();
