using AutoMapper;
using Core.Identity;
using Core.Security.Requests;
using Core.Security.Responses;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Security.Mapping;
public class GeneralMapperProfile : Profile
{
    public GeneralMapperProfile()
    {
        CreateMap<ApplicationUser, UserResponse>().ReverseMap();
        CreateMap<ApplicationUser, RegisterResponse>().ReverseMap();
        CreateMap<ApplicationUser, RegisterRequest>().ReverseMap();
    }
}