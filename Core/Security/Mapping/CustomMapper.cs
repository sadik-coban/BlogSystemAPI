using AutoMapper;
using AutoMapper.Internal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Security.Mapping;
public class CustomMapper
{
    private static readonly Lazy<IMapper> lazy = new Lazy<IMapper>(() => {
        var config = new MapperConfiguration(config =>
        {
            config.Internal().MethodMappingEnabled = false;
            config.AddProfile<GeneralMapperProfile>();
        });
        return config.CreateMapper();
    });
    public static IMapper Mapper => lazy.Value;
}
