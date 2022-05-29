using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;

namespace identity_server;

public class TokenService : IDisposable
{
    private bool _disposed = false;
    private readonly ILogger<TokenService> _logger;

    private readonly IDictionary<string, IIdentity> _codes = new Dictionary<string, IIdentity>();


    public TokenService(ILogger<TokenService> logger)
    {
        _logger = logger;
    }

    public string GenerateCode(IIdentity identity)
    {
        var code = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));
        _codes[code] = identity;
        return code;
    }

    private static string GenerateToken(IIdentity identity)
    {
        var secret = "yadayada1234yadayada1234";
        var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret));
        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(identity),
            Expires = DateTime.UtcNow.AddHours(1),
            Issuer = "https://localhost:7227",
            Audience = "<not implemented>",
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
        };
        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(descriptor);
        return handler.WriteToken(token);
    }


    public string GetToken(string code)
    {
        var identity = _codes[code];

        return GenerateToken(identity);
    }

    public void Dispose()
    {
        if (_disposed) return;

        _disposed = true;
    }
}