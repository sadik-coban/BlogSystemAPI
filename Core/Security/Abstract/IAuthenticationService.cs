using Core.ResultObjects;
using Core.Security.Requests;
using Core.Security.Responses;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Security.Abstract;
public interface IAuthenticationService
{
    Task<Result<TokenResponse>> CreateTokenAsync(LoginRequest loginRequest);
    Task<Result<TokenResponse>> CreateTokenByRefreshTokenAsync(string refreshToken);
    Task<Result<NoContent>> RevokeRefreshToken(string refreshToken);
}
