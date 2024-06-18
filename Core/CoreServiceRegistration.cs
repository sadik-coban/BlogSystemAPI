using Core.Data;
using Core.External.Abstract;
using Core.External.Concrete;
using Core.External.Options;
using Core.Identity;
using Core.Security.Abstract;
using Core.Security.Concrete;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NETCore.MailKit.Core;
using NETCore.MailKit.Extensions;
using NETCore.MailKit.Infrastructure.Internal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core;
public static class CoreServiceRegistration
{
    public static IServiceCollection AddCoreServices(this IServiceCollection services, IConfiguration configuration, EmailOptions emailOptions)
    {
        //var connectionString = configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
        services.AddTransient<IEmailSender<ApplicationUser>, EmailSender>();
        services.AddMailKit(optionBuilder =>
        {
            optionBuilder.UseMailKit(new MailKitOptions()
            {
                Server = emailOptions.Server,
                Port = emailOptions.Port,
                SenderName = emailOptions.SenderName,
                SenderEmail = emailOptions.SenderEmail,

                // can be optional with no authentication 
                Account = emailOptions.Account,
                Password = emailOptions.Password,

                // enable ssl or tls
                Security = emailOptions.Security
            });
        });
        services.AddTransient<IEmailService, EmailService>();
        services.AddScoped<IAuthenticationService, AuthenticationService>();
        services.AddScoped<IUserService, UserService>();
        services.AddScoped<ITokenService, TokenService>();
        return services;
    }
}