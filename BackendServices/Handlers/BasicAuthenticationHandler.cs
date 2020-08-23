using BackendServices.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace BackendServices.Handlers
{
    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private BookStoreContext _ctx;

        public BasicAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            BookStoreContext ctx): base(options,logger,encoder,clock)
        {
            _ctx = ctx;
        }
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.Fail("Authorization header was not found");

            try
            {
      
          var authAutherizationheadervalue = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);

            var bytes = Convert.FromBase64String(authAutherizationheadervalue.Parameter);

            string[] credentials = Encoding.UTF8.GetString(bytes).Split(" ");
            string email = credentials[0];
            string password = credentials[1];

            User _user = _ctx.User.Where(usr => usr.Password == password && usr.EmailAddress == email).FirstOrDefault();

            if (_user == null)
            {
                return AuthenticateResult.Fail("Wrong user name or password");
            }
            else
            {
                var claims = new[] { new Claim(ClaimTypes.Name, _user.EmailAddress) };
                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principle = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principle, Scheme.Name);

                return AuthenticateResult.Success(ticket);
            }

        }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail("Error has Occured");
            } 
        }
    }
}
