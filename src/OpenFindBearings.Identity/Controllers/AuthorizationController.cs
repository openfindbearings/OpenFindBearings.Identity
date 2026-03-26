using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenFindBearings.Identity.Controllers
{
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly ILogger<AuthorizationController> _logger; 

        public AuthorizationController(IOpenIddictApplicationManager applicationManager, IOpenIddictScopeManager scopeManager, ILogger<AuthorizationController> logger)
        {
            _applicationManager = applicationManager;
            _scopeManager = scopeManager;
            _logger = logger;
        }

        [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            _logger.LogInformation("收到Token请求: GrantType={GrantType}, ClientId={ClientId}", request.GrantType, request.ClientId);

            if (request.IsClientCredentialsGrantType())
            {
                // Note: the client credentials are automatically validated by OpenIddict:
                // if client_id or client_secret are invalid, this action won't be invoked.

                var application = await _applicationManager.FindByClientIdAsync(request.ClientId!);
                if (application == null)
                {
                    _logger.LogWarning("客户端凭证模式: 客户端不存在 {ClientId}", request.ClientId);
                    throw new InvalidOperationException("The application details cannot be found in the database.");
                }

                // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                var identity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // Add the claims that will be persisted in the tokens (use the client_id as the subject identifier).
                identity.SetClaim(Claims.Subject, await _applicationManager.GetClientIdAsync(application));
                identity.SetClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application));

                // Note: In the original OAuth 2.0 specification, the client credentials grant
                // doesn't return an identity token, which is an OpenID Connect concept.
                //
                // As a non-standardized extension, OpenIddict allows returning an id_token
                // to convey information about the client application when the "openid" scope
                // is granted (i.e specified when calling principal.SetScopes()). When the "openid"
                // scope is not explicitly set, no identity token is returned to the client application.

                // Set the list of scopes granted to the client application in access_token.
                identity.SetScopes(request.GetScopes());
                identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
                identity.SetDestinations(GetDestinations);

                var scopes = request.GetScopes();
                _logger.LogInformation("客户端凭证模式: ClientId={ClientId}, Scopes={Scopes}", request.ClientId, scopes.IsDefaultOrEmpty ? "none" : string.Join(",", scopes));

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            _logger.LogWarning("不支持的授权类型: {GrantType}", request.GrantType);
            throw new NotImplementedException("The specified grant type is not implemented.");
        }

        private static IEnumerable<string> GetDestinations(Claim claim)
        {
            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.

            return claim.Type switch
            {
                Claims.Name or Claims.Subject => [Destinations.AccessToken, Destinations.IdentityToken],
                _ => [Destinations.AccessToken],
            };
        }
    }
}
