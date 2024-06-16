using Core.ResultObjects;
using Core.Security.Requests;
using Core.Security.Responses;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Security.Abstract;
public interface IUserService
{
    Task<Result<RegisterResponse>> CreateUserAsync(RegisterRequest registerRequest);
    Task<Result<UserResponse>> GetUserByNameAsync(string userName);
}
