using Core.Identity;
using Core.ResultObjects;
using Core.Security.Requests;
using Core.Security.Responses;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Core.Security.Abstract;
public interface IAuthenticationService
{
    Task<SignInResult> CheckPasswordSignInAsync(LoginRequest loginDto);
    Task<Result<TokenResponse>> CreateTokenAsync(LoginRequest loginRequest);
    Task<Result<TokenResponse>> CreateTokenByRefreshTokenAsync(string refreshToken);
    Task<Result<NoContent>> RevokeRefreshTokenAsync(string refreshToken);
    Task<Result<NoContent>> RevokeAllRefreshTokensAsync(Guid userId, string refreshToken);
    Task<IdentityResult> ChangePasswordAsync(ChangePasswordRequest model, ClaimsPrincipal User);
    Task<IdentityResult> ConfirmEmailAsync(Guid id, string token);
    Task<IdentityResult> SendPasswordResetLinkAsync(ApplicationUser user, string url);
    Task<IdentityResult> ResetPasswordAsync(CreateNewPasswordRequest model);
    Task<IdentityResult> SendEmailChangeLinkAsync(ApplicationUser user, string email, string url);
    Task<IdentityResult> ChangeEmailAndUserNameAsync(Guid id, string email, string token);
}
