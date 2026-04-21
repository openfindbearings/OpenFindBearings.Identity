using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.Scripting;
using Microsoft.IdentityModel.Tokens;
using OpenFindBearings.Identity.Constants;
using OpenFindBearings.Identity.Data.Repositories;
using OpenFindBearings.Identity.Helpers;
using OpenFindBearings.Identity.Models.Enums;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenFindBearings.Identity.Controllers
{
    public class AuthorizationController : Controller
    {
        private readonly IClientRepository _clientRepository;
        private readonly IScopeRepository _scopeRepository;
        private readonly IUserRepository _userRepository;
        private readonly ILogger<AuthorizationController> _logger; 

        public AuthorizationController(IClientRepository clientRepository, IScopeRepository scopeRepository, IUserRepository userRepository, ILogger<AuthorizationController> logger)
        {
            _clientRepository = clientRepository;
            _scopeRepository = scopeRepository;
            _userRepository = userRepository;

            _logger = logger;
        }

        [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            _logger.LogInformation("收到Token请求: GrantType={GrantType}, ClientId={ClientId}", request.GrantType, request.ClientId);

            return request.GrantType switch
            {
                GrantTypeConstants.ClientCredentials => await HandleClientCredentialsAsync(request),
                GrantTypeConstants.Password => await HandlePasswordAsync(request),
                GrantTypeConstants.Sms => await HandleSmsCodeAsync(request),
                GrantTypeConstants.WeChat => await HandleWeChatAsync(request),
                GrantTypeConstants.QQ => await HandleQQAsync(request),
                GrantTypeConstants.Biometric => await HandleBiometricAsync(request),
                GrantTypeConstants.RefreshToken => await HandleRefreshTokenAsync(request),
                _ => Forbid(),
            };
        }

        private async Task<IActionResult> HandleRefreshTokenAsync(OpenIddictRequest request)
        {
            if (request.IsRefreshTokenGrantType())
            {
                // OpenIddict 自动验证刷新令牌
                // 如果无效，请求不会被路由到这个方法

                // 创建新令牌
                var identity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // 使用 client_id 作为 subject（客户端凭证模式）
                identity.SetClaim(Claims.Subject, request.ClientId);
                identity.SetClaim(Claims.Name, request.ClientId);

                // 设置 scopes
                var scopes = request.GetScopes();
                identity.SetScopes(scopes);
                identity.SetResources(await _scopeRepository.ListResourcesAsync(identity));
                identity.SetDestinations(GetDestinations);

                _logger.LogInformation("刷新令牌: ClientId={ClientId}, Scopes={Scopes}", request.ClientId, scopes);

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            _logger.LogWarning("不支持的刷新令牌授权类型");
            throw new InvalidOperationException("The refresh token grant is not properly configured.");
        }

        private async Task<IActionResult> HandleBiometricAsync(OpenIddictRequest request)
        {
            throw new NotImplementedException();
        }

        private async Task<IActionResult> HandleQQAsync(OpenIddictRequest request)
        {
            throw new NotImplementedException();
        }

        private async Task<IActionResult> HandleWeChatAsync(OpenIddictRequest request)
        {
            throw new NotImplementedException();
        }

        private async Task<IActionResult> HandleSmsCodeAsync(OpenIddictRequest request)
        {
            throw new NotImplementedException();
        }

        private async Task<IActionResult> HandlePasswordAsync(OpenIddictRequest request)
        {
            if (request.IsPasswordGrantType())
            {
                var user = await _userRepository.GetByUsernameAsync(request.Username!);
                if (user == null)
                {
                    var properties = new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The username/password couple is invalid."
                    });

                    return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                // Validate the username/password parameters and ensure the account is not locked out.       
                var result = user.CheckPassword(request.Password!, PasswordHasher.Verify);
                if (result)
                {
                    var properties = new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The username/password couple is invalid."
                    });

                    return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                var identity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // Add the claims that will be persisted in the tokens.
                identity.SetClaim(Claims.Subject, user.Sub)
                        .SetClaim(Claims.Email, user.Email)
                        .SetClaim(Claims.Name, user.Name)
                        .SetClaim(Claims.PreferredUsername, request.Username!)
                        .SetClaims(Claims.Role, [.. (string[])user.CustomClaims!["roles"]]);

                // Set the list of scopes granted to the client application.
                identity.SetScopes(new[]
                {
                    Scopes.OpenId,
                    Scopes.Email,
                    Scopes.Profile,
                    Scopes.Roles
                }.Intersect(request.GetScopes()));

                identity.SetDestinations(GetDestinations);

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            _logger.LogWarning("不支持的授权类型: {GrantType}", request.GrantType);
            throw new NotImplementedException("The specified grant type is not implemented.");
        }

        private async Task<IActionResult> HandleClientCredentialsAsync(OpenIddictRequest request)
        {
            if (request.IsClientCredentialsGrantType())
            {
                // Note: the client credentials are automatically validated by OpenIddict:
                // if client_id or client_secret are invalid, this action won't be invoked.

                var client = await _clientRepository.GetByClientIdAsync(request.ClientId!);
                if (client == null)
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
                identity.SetClaim(Claims.Subject, client.ClientId);
                identity.SetClaim(Claims.Name, client.DisplayName);

                // Note: In the original OAuth 2.0 specification, the client credentials grant
                // doesn't return an identity token, which is an OpenID Connect concept.
                //
                // As a non-standardized extension, OpenIddict allows returning an id_token
                // to convey information about the client application when the "openid" scope
                // is granted (i.e specified when calling principal.SetScopes()). When the "openid"
                // scope is not explicitly set, no identity token is returned to the client application.

                // Set the list of scopes granted to the client application in access_token.
                var scopes = request.GetScopes();
                identity.SetScopes(scopes);
                identity.SetResources(await _scopeRepository.ListResourcesAsync(identity));
                identity.SetDestinations(GetDestinations);
                
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

            switch (claim.Type)
            {
                case Claims.Name or Claims.PreferredUsername:
                    yield return Destinations.AccessToken;

                    if (claim.Subject!.HasScope(Scopes.Profile))
                        yield return Destinations.IdentityToken;

                    yield break;

                case Claims.Email:
                    yield return Destinations.AccessToken;

                    if (claim.Subject!.HasScope(Scopes.Email))
                        yield return Destinations.IdentityToken;

                    yield break;

                case Claims.Role:
                    yield return Destinations.AccessToken;

                    if (claim.Subject!.HasScope(Scopes.Roles))
                        yield return Destinations.IdentityToken;

                    yield break;

                // Never include the security stamp in the access and identity tokens, as it's a secret value.
                case "AspNet.Identity.SecurityStamp": yield break;

                default:
                    yield return Destinations.AccessToken;
                    yield break;
            }
        }
    }
}
