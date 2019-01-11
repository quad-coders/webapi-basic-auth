using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Filters;
using System.Web.Http.Results;

namespace WebAPI.Security
{
    public class BasicAuthAttribute : ActionFilterAttribute, IAuthenticationFilter
    {
        public override bool AllowMultiple
        {
            get
            {
                return false;
            }
        }

        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            // Look for credentials in the request
            HttpRequestMessage request = context.Request;
            var authParam = request.Headers.Authorization?.Parameter;

            if (authParam == null)
            {
                var errorResult = new ResponseMessageResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
                context.ErrorResult = errorResult;
                return;
            }

            // Decode credential
            var decodedAuth = Encoding.UTF8.GetString(Convert.FromBase64String(authParam));
            var userName = decodedAuth.Substring(0, decodedAuth.IndexOf(":"));
            var password = decodedAuth.Substring(decodedAuth.IndexOf(":") + 1);

            // Validate credential
            IPrincipal principal = await this.AuthenticateAsync(userName, password, cancellationToken);
            if (principal == null)
            {
                var errorResult = new ResponseMessageResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
                context.ErrorResult = errorResult;
            }
            else
            {
                context.Principal = principal;
            }
        }

        public async Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            var response = await context.Result.ExecuteAsync(cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                // Add challenge to header
                var errorResult = new UnauthorizedResult(new List<AuthenticationHeaderValue> { new AuthenticationHeaderValue("Basic") }, new HttpRequestMessage());
                context.Result = errorResult;
            }

            return;
        }

        private async Task<IPrincipal> AuthenticateAsync(string userName, string password, CancellationToken cancellationToken)
        {
            // Authenticate users

            // Don't use this code in production
            return await Task.Factory.StartNew(() => new GenericPrincipal(new GenericIdentity(userName), null));
        }
    }
}