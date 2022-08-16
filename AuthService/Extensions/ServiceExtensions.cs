using AuthService.Application.Abstract.Service;
using AuthService.Application.Common;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using FluentValidation.AspNetCore;
using System.Reflection;
using System.Security.Claims;
using AuthService.Application.Abstract.DataService;
using AuthService.Persistence.DataServices;
using System.Text;
using AutoMapper;

namespace AuthService.Extensions
{
    public static partial class ServiceExtensions
    {
        /// <summary>
        /// configure authentication
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        public static void ConfigureAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            // jwt wire up
            var jwtAppSettingOptions = configuration.GetSection(nameof(JwtIssuerOptions));
            var signInKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtAppSettingOptions[nameof(JwtIssuerOptions.IssuerSigningKey)]));

            // Configure JwtIssuerOptions
            services.Configure<JwtIssuerOptions>(options =>
            {
                options.Issuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)];
                options.Audience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)];
                options.SigningCredentials = new SigningCredentials(signInKey, SecurityAlgorithms.HmacSha256);
            });

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)],

                ValidateAudience = true,
                ValidAudience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)],

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signInKey,

                RequireExpirationTime = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            services.AddAuthentication(opt =>
            {
                opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(configureOptions =>
            {
                configureOptions.ClaimsIssuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)];
                configureOptions.TokenValidationParameters = tokenValidationParameters;
                configureOptions.SaveToken = true;

                configureOptions.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        {
                            context.Response.Headers.Add("Token-Expired", "true");
                        }
                        return Task.CompletedTask;
                    }
                };
            });
        }

        /// <summary>
        /// configure authorization
        /// </summary>
        /// <param name="services"></param>
        public static void ConfigureAuthorization(this IServiceCollection services)
        {
            // api user claim policy
            services.AddAuthorization(options =>
            {
                options.AddPolicy("ApiUser",
                    policy => policy.RequireClaim(ClaimTypes.Role));
            });
        }

        /// <summary>
        /// configure fluent validation
        /// </summary>
        /// <param name="services"></param>
        public static void ConfigureFluentValidaton(this IServiceCollection services)
        {
            services.AddFluentValidation(conf =>
            {
                conf.RegisterValidatorsFromAssembly(Assembly.GetExecutingAssembly());
                conf.AutomaticValidationEnabled = false;
            });
        }

        /// <summary>
        /// configure automapper
        /// </summary>
        /// <param name="services"></param>
        public static void ConfigureAutoMapper(this IServiceCollection services)
        {
            var config = new MapperConfiguration(config =>
            {
                config.AddProfile(new AutoMapperProfile());
            });

            services.AddSingleton(config.CreateMapper());
        }

        /// <summary>
        /// configure dependency injection
        /// </summary>
        /// <param name="services"></param>
        public static void ConfigureDependency(this IServiceCollection services)
        {
            // setup dependenvy here
            //db context
            // services.AddScoped<IGlocalDbContext, GlocalDbContext>();

            // services
            //services.AddTransient<IJwtService, JwtService>();
            services.AddTransient<IAuthService, Application.Concrete.AuthService>();

            // data services
            services.AddTransient<IUserDataService, UserDataService>();
        }
    }
}
