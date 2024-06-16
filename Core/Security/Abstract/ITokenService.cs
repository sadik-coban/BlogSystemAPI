using Core.Identity;
using Core.Security.Responses;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Security.Abstract;
public interface ITokenService
{
    Task<TokenResponse> CreateTokenAsync(ApplicationUser applicationUser);
}
