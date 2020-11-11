using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.EntityFrameworkCore;
using WebAppSecure.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.Twitter;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Security.Cryptography;
using System.Text;

namespace WebAppSecure
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));
            
            services.AddRazorPages();
            services.AddControllers();

            services.AddIdentity<IdentityUser, IdentityRole>(options => options.SignIn.RequireConfirmedAccount = false)
               .AddEntityFrameworkStores<ApplicationDbContext>()
               .AddDefaultUI()               
               .AddDefaultTokenProviders();

            //var issuerSigningCertificate = new SigningIssuerCertificate();
            RsaSecurityKey issuerSigningKey = GetIssuerSigningKey();

            services.AddAuthentication()
              .AddTwitter(twitterOptions =>
              {
                  twitterOptions.ConsumerKey = Configuration["Authentication:Twitter:ConsumerAPIKey"];
                  twitterOptions.ConsumerSecret = Configuration["Authentication:Twitter:ConsumerSecret"];
                  twitterOptions.RetrieveUserDetails = true;
              })
              .AddJwtBearer(options =>
               {
                   options.TokenValidationParameters = new TokenValidationParameters
                   {               
                        IssuerSigningKey = issuerSigningKey,
                   };
              });

            services.AddCors(options =>
            {
                options.AddDefaultPolicy(
                    builder =>
                    {
                        builder.AllowAnyOrigin();
                        builder.AllowAnyHeader();
                        builder.AllowAnyMethod();
                    });
            });
        }

        private RsaSecurityKey GetIssuerSigningKey()
        {
            using var rsa = new RSACryptoServiceProvider();

            string publicKeyString = "4359EqA4YLmJvVxxIcwK4O7mHCXczo4ou/d2nVbOznSm5XeqtwY1EslN8uDaQGPX1xuvkAkfX9sEtWclgoId+A0GmrE/uZIu2TRbmPYws9qqwdBhNmroh5qygn4tyuyejPqNu8QshPO3uz6rHHrUeblCJW7bGWkNmrUbMZ/aoQgEpcsQurYURRKijuKI6IhFfMolVqB7GE9O72McmiLe65FH33QDiaVH4FRYsyFKPWdyj1qGl+d9l9a2NpvHd+vBVQY2c0SfSWMFQugdsKmo7gkPmZPv69RW2ErCWUPc9IgVuD+0fI+lX/K0lBWfChBkMLXdU5rUZRVGcDw+3CdCGQ==";

            var p = new RSAParameters() { Modulus = Encoding.Unicode.GetBytes(publicKeyString), Exponent = Encoding.Unicode.GetBytes("AQAB") };

            rsa.ImportParameters(p);

            return new RsaSecurityKey(rsa);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
                app.UseCors();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
                endpoints.MapControllers();
            });
        }
    }
}
