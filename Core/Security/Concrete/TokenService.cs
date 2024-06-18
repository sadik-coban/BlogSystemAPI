using Core.Identity;
using Core.Security.Abstract;
using Core.Security.Options;
using Core.Security.Responses;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;


namespace Core.Security.Concrete;
public class TokenService : ITokenService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly CustomTokenOptions _tokenOptions;

    public TokenService(UserManager<ApplicationUser> userManager, IOptions<CustomTokenOptions> tokenOptions)
    {
        _userManager = userManager;
        _tokenOptions = tokenOptions.Value;
    }

    private async Task<IEnumerable<Claim>> GetClaimsAsync(ApplicationUser appUser, List<string> audiences)
    {
        var userRoles = await _userManager.GetRolesAsync(appUser);

        var claimList = new List<Claim>{
                new Claim(JwtRegisteredClaimNames.Sub, appUser.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, appUser.Email),
                new Claim(ClaimTypes.Name, appUser.Name),
            };

        claimList.AddRange(audiences.Select(x => new Claim(JwtRegisteredClaimNames.Aud, x)));

        claimList.AddRange(userRoles.Select(x => new Claim(ClaimTypes.Role, x)));
        return claimList;
    }

    private string CreateRefreshToken()
    {
        var numberByte = new byte[32];
        using (var rnd = RandomNumberGenerator.Create())
        {
            rnd.GetBytes(numberByte);
        }
        return Convert.ToBase64String(numberByte);
    }

    public async Task<TokenResponse> CreateTokenAsync(ApplicationUser appUser)
    {
        var accessTokenExpiration = DateTime.Now.AddMinutes(_tokenOptions.AccessTokenExpiration);
        var refreshTokenExpiration = DateTime.Now.AddMinutes(_tokenOptions.RefreshTokenExpiration);
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_tokenOptions.SecurityKey));
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
        var claimList = await GetClaimsAsync(appUser, _tokenOptions.Audiences);
        var jwtSecurityToken = new JwtSecurityToken(
            issuer: _tokenOptions.Issuer,
            expires: accessTokenExpiration,
            claims: claimList,
            signingCredentials: signingCredentials
        );
        var handler = new JwtSecurityTokenHandler();
        var token = handler.WriteToken(jwtSecurityToken);
        var tokenDto = new TokenResponse
        {
            AccessToken = token,
            AccessTokenExpiration = accessTokenExpiration,
            RefreshToken = CreateRefreshToken(),
            RefreshTokenExpiration = refreshTokenExpiration,
        };
        return tokenDto;
    }

    public async Task<string> GenerateEmailConfirmationTokenAsync(ApplicationUser user)
    {
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        return token;
    }
    public async Task<string> GeneratePasswordResetTokenAsync(ApplicationUser user)
    {
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        return token;
    }
    public async Task<string> GenerateEmailChangeTokenAsync(ApplicationUser user, string newEmail)
    {
        var token = await _userManager.GenerateChangeEmailTokenAsync(user, newEmail);
        return token;
    }

}
