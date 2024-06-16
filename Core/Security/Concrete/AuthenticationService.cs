using Core.Data;
using Core.Identity;
using Core.ResultObjects;
using Core.Security.Abstract;
using Core.Security.Requests;
using Core.Security.Responses;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Security.Concrete;
public class AuthenticationService : IAuthenticationService
{
    private readonly ITokenService _tokenService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IGenericRepository<RefreshToken> _userRefreshTokenService;

    public AuthenticationService(
        ITokenService tokenService,
        UserManager<ApplicationUser> userManager,
        IUnitOfWork unitOfWork,
        IGenericRepository<RefreshToken> userRefreshTokenService)
    {
        _tokenService = tokenService;
        _userManager = userManager;
        _unitOfWork = unitOfWork;
        _userRefreshTokenService = userRefreshTokenService;
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
            return Result<TokenResponse>.Fail("Eposta adresi veya parola hatalı", 400);
        }
        if (!await _userManager.CheckPasswordAsync(user, loginDto.Password))
        {
            return Result<TokenResponse>.Fail("Eposta adresi veya parola hatalı", 400);
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
}