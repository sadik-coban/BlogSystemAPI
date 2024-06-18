using Core.Data;
using Core.Identity;
using Core.ResultObjects;
using Core.Security.Abstract;
using Core.Security.Requests;
using Core.Security.Responses;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Core.Security.Concrete;
public class AuthenticationService : IAuthenticationService
{
    private readonly ITokenService _tokenService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IGenericRepository<RefreshToken> _userRefreshTokenService;
    private readonly External.Abstract.IEmailSender<ApplicationUser> _emailService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly SignInManager<ApplicationUser> _signInManager;
    public AuthenticationService(
        ITokenService tokenService,
        UserManager<ApplicationUser> userManager,
        IUnitOfWork unitOfWork,
        IGenericRepository<RefreshToken> userRefreshTokenService,
        External.Abstract.IEmailSender<ApplicationUser> emailService,
        IHttpContextAccessor httpContextAccessor,
        SignInManager<ApplicationUser> signInManager)
    {
        _emailService = emailService;
        _tokenService = tokenService;
        _userManager = userManager;
        _unitOfWork = unitOfWork;
        _userRefreshTokenService = userRefreshTokenService;
        _httpContextAccessor = httpContextAccessor;
        _signInManager = signInManager;
    }

    public async Task<SignInResult> CheckPasswordSignInAsync(LoginRequest loginDto)
    {
        var user = await _userManager.FindByEmailAsync(loginDto.Email);
        if (user == null)
        {
            return SignInResult.Failed;
        }
        var result = await _signInManager
        .CheckPasswordSignInAsync(user, loginDto.Password, false);
        return result;
    }

    public async Task<Result<TokenResponse>> CreateTokenAsync(LoginRequest loginDto)
    {
        if (loginDto == null)
        {
            throw new ArgumentNullException(nameof(loginDto));
        }
        var user = await _userManager.FindByEmailAsync(loginDto.Email);
        if (user == null)
        {
            return Result<TokenResponse>.Fail("Eposta adresi veya parola hatalı", 401);
        }
        var result = await _signInManager
                .CheckPasswordSignInAsync(user, loginDto.Password, false);
        if (!result.Succeeded)
        {
            return Result<TokenResponse>.Fail("Hatalı Giriş", 401);
        }
        var token = await _tokenService.CreateTokenAsync(user);
        await _userRefreshTokenService.AddAsync(
            new RefreshToken
            {
                ApplicationUserId = user.Id,
                Code = token.RefreshToken,
                ExpirationDate = token.RefreshTokenExpiration
            }
        );
        await _unitOfWork.CommitAsync();
        return Result<TokenResponse>.Success(token, 201);
    }

    public async Task<Result<TokenResponse>> CreateTokenByRefreshTokenAsync(string refreshToken)
    {
        var existRefreshToken = await _userRefreshTokenService
            .Where(x => x.Code == refreshToken)
            .SingleOrDefaultAsync();
        if (existRefreshToken == null)
        {
            return Result<TokenResponse>.Fail("Refresh token bulunamadı", 404);
        }
        var user = await _userManager.FindByIdAsync(existRefreshToken.ApplicationUserId.ToString());
        if (user == null)
        {
            return Result<TokenResponse>.Fail("Kullanıcı bulunamadı", 404);
        }
        var tokenDto = await _tokenService.CreateTokenAsync(user);
        existRefreshToken.Code = tokenDto.RefreshToken;
        existRefreshToken.ExpirationDate = tokenDto.RefreshTokenExpiration;
        await _unitOfWork.CommitAsync();
        return Result<TokenResponse>.Success(tokenDto, 201);
    }

    public async Task<Result<NoContent>> RevokeRefreshTokenAsync(string refreshToken)
    {
        var existRefreshToken = await _userRefreshTokenService
            .Where(x => x.Code == refreshToken)
            .SingleOrDefaultAsync();
        if (existRefreshToken == null)
        {
            return Result<NoContent>.Fail("Refresh token bulunamadı", 404);
        }
        _userRefreshTokenService.Remove(existRefreshToken);
        await _unitOfWork.CommitAsync();
        return Result<NoContent>.Success(201);
    }

    public async Task<Result<NoContent>> RevokeAllRefreshTokensAsync(Guid userId, string refreshToken)
    {
        var existRefreshToken = await _userRefreshTokenService
            .Where(x => x.Code == refreshToken)
            .SingleOrDefaultAsync();
        if (existRefreshToken == null)
        {
            return Result<NoContent>.Fail("Refresh token bulunamadı", 404);
        }

        var existRefreshTokens = await _userRefreshTokenService
            .Where(x => x.ApplicationUserId == userId)
            .ExecuteDeleteAsync();

        return Result<NoContent>.Success(201);
    }


    public async Task<Result<NoContent>> RevokeAllRefreshTokensExceptThisAsync(Guid userId, string refreshToken)
    {
        var existRefreshToken = await _userRefreshTokenService
            .Where(x => x.Code == refreshToken)
            .SingleOrDefaultAsync();
        if (existRefreshToken == null)
        {
            return Result<NoContent>.Fail("Refresh token bulunamadı", 404);
        }

        var existRefreshTokens = await _userRefreshTokenService
            .Where(x => x.ApplicationUserId == userId && x.Code != refreshToken)
            .ExecuteDeleteAsync();

        return Result<NoContent>.Success(201);
    }


    public async Task<Result<NoContent>> RevokeAllRefreshTokensWithoutValidationAsync(Guid userId)
    {
        var existRefreshTokens = await _userRefreshTokenService
            .Where(x => x.ApplicationUserId == userId)
            .ExecuteDeleteAsync();
        return Result<NoContent>.Success(201);
    }

    //public async Task<Result<NoContent>> RevokeAllRefreshTokensAsync(Guid userId, string? refreshToken)
    //{
    //    Result<NoContent> revokeResult;
    //    if (refreshToken == null)
    //    {
    //        refreshToken = _httpContextAccessor.HttpContext.Request.Cookies["RefreshToken"];
    //        if (refreshToken == null)
    //        {
    //            return Result<NoContent>.Fail("Refresh token bulunamadı",401);
    //        }
    //        revokeResult = await RevokeRefreshTokensAsyncBase(userId, refreshToken);
    //        if (!revokeResult.IsSuccessed)
    //        {
    //            return revokeResult;
    //        }
    //        _httpContextAccessor.HttpContext.Response.Cookies.Delete("AccessToken");
    //        _httpContextAccessor.HttpContext.Response.Cookies.Delete("RefreshToken");
    //        return revokeResult;
    //    }
    //    revokeResult = await RevokeRefreshTokensAsyncBase(userId, refreshToken);
    //    return revokeResult;
    //}

    public async Task<IdentityResult> ChangePasswordAsync(ChangePasswordRequest model, ClaimsPrincipal User)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return IdentityResult.Failed(new IdentityError() { Description = "User Not Found" });
        }
        var result = await _userManager.ChangePasswordAsync(user!, model.CurrentPassword, model.NewPassword);
        return result;
    }
    public async Task<IdentityResult> ConfirmEmailAsync(Guid id, string token)
    {
        var user = await _userManager.FindByIdAsync(id.ToString());
        if (user is null)
        {
            return IdentityResult.Failed(new IdentityError() { Description = "User Not Found" });
        }
        var result = await _userManager.ConfirmEmailAsync(user, token);
        return result;
    }
    public async Task<IdentityResult> SendPasswordResetLinkAsync(ApplicationUser user, string url)
    {
        if (user is null)
        {
            return IdentityResult.Failed(new IdentityError() { Description = "User Not Found" });
        }
        await _emailService.SendPasswordResetLinkAsync(user, user.Email, url);
        return IdentityResult.Success;
    }
    public async Task<IdentityResult> ResetPasswordAsync(CreateNewPasswordRequest model)
    {
        var user = await _userManager.FindByIdAsync(model.Id.ToString());
        if (user is null)
        {
            return IdentityResult.Failed(new IdentityError() { Description = "User Not Found" });
        }
        var result = await _userManager.ResetPasswordAsync(user!, model.Token, model.NewPassword);
        return result;
    }
    public async Task<IdentityResult> SendEmailChangeLinkAsync(ApplicationUser user, string email, string url)
    {
        if (user is null)
        {
            return IdentityResult.Failed(new IdentityError() { Description = "User Not Found" });
        }
        await _emailService.SendEmailChangeLinkAsync(user, email, url);
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> ChangeEmailAndUserNameAsync(Guid id, string email, string token)
    {
        var user = await _userManager.FindByIdAsync(id.ToString());
        var result = await _userManager.ChangeEmailAsync(user, email, token);
        if (result.Succeeded)
        {
            var resultUserName = await _userManager.SetUserNameAsync(user, email);
            return resultUserName;
        }
        return result;
    }

}