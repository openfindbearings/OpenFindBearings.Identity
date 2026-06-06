using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenFindBearings.Identity.Constants;
using OpenFindBearings.Identity.Services.Interfaces;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenFindBearings.Identity.Controllers
{
    /// <summary>
    /// 授权控制器 - 处理 OAuth 2.0 / OIDC 令牌请求
    /// </summary>
    public class AuthorizationController : Controller
    {
        private readonly IUserService _userService;
        private readonly IClientService _clientService;
        private readonly IScopeService _scopeService;
        private readonly ILogger<AuthorizationController> _logger;

        public AuthorizationController(
            IUserService userService,
            IClientService clientService,
            IScopeService scopeService,
            ILogger<AuthorizationController> logger)
        {
            _userService = userService;
            _clientService = clientService;
            _scopeService = scopeService;
            _logger = logger;
        }

        /// <summary>
        /// Token 端点 - 处理所有授权类型的令牌请求
        /// </summary>
        [HttpPost("~/connect/token")]
        [IgnoreAntiforgeryToken]
        [Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest()
                ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            _logger.LogInformation("收到 Token 请求: GrantType={GrantType}, ClientId={ClientId}", request.GrantType, request.ClientId);

            return request.GrantType switch
            {
                GrantTypeConstants.ClientCredentials => await HandleClientCredentialsAsync(request),
                GrantTypeConstants.Password => await HandlePasswordAsync(request),
                GrantTypeConstants.RefreshToken => await HandleRefreshTokenAsync(request),
                GrantTypeConstants.Sms => await HandleSmsCodeAsync(request),
                GrantTypeConstants.WeChat => await HandleWeChatAsync(request),
                GrantTypeConstants.QQ => await HandleQQAsync(request),
                GrantTypeConstants.Biometric => await HandleBiometricAsync(request),
                _ => Forbid()
            };
        }

        #region 授权类型处理

        /// <summary>
        /// 处理客户端凭证授权 (client_credentials)
        /// </summary>
        private async Task<IActionResult> HandleClientCredentialsAsync(OpenIddictRequest request)
        {
            if (!request.IsClientCredentialsGrantType())
            {
                _logger.LogWarning("不支持的授权类型: {GrantType}", request.GrantType);
                throw new NotImplementedException("The specified grant type is not implemented.");
            }

            // 验证客户端是否存在
            var client = await _clientService.GetByClientIdAsync(request.ClientId!);
            if (client == null)
            {
                _logger.LogWarning("客户端凭证模式: 客户端不存在 {ClientId}", request.ClientId);
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The client application is not found."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 创建身份标识
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // 添加客户端声明
            identity.SetClaim(Claims.Subject, client.ClientId);
            identity.SetClaim(Claims.Name, client.DisplayName);

            // 设置作用域
            var scopes = request.GetScopes().ToList();
            identity.SetScopes(scopes);
            identity.SetResources(await GetScopeResourcesAsync(scopes));
            identity.SetDestinations(GetDestinations);

            _logger.LogInformation("客户端凭证模式: ClientId={ClientId}, Scopes={Scopes}",
                request.ClientId, scopes.Count == 0 ? "none" : string.Join(",", scopes));

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        /// <summary>
        /// 处理密码授权 (password)
        /// </summary>
        private async Task<IActionResult> HandlePasswordAsync(OpenIddictRequest request)
        {
            if (!request.IsPasswordGrantType())
            {
                _logger.LogWarning("不支持的授权类型: {GrantType}", request.GrantType);
                throw new NotImplementedException("The specified grant type is not implemented.");
            }

            // 验证用户名和密码
            var user = await _userService.GetByUsernameAsync(request.Username!);
            if (user == null)
            {
                _logger.LogWarning("密码模式: 用户不存在 {Username}", request.Username);
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 检查用户是否可以登录 - 使用 Service 方法
            var canLogin = await _userService.CheckCanLoginAsync(user.Id);
            if (!canLogin)
            {
                _logger.LogWarning("密码模式: 用户无法登录 {Username}", request.Username);
                await _userService.RecordLoginFailureAsync(user.Id);
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The account is not available."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 验证密码
            var isValidPassword = await _userService.CheckPasswordAsync(user.Id, request.Password!);
            if (!isValidPassword)
            {
                _logger.LogWarning("密码模式: 密码错误 {Username}", request.Username);
                await _userService.RecordLoginFailureAsync(user.Id);
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 记录登录成功
            await _userService.RecordLoginSuccessAsync(user.Id, HttpContext.Connection.RemoteIpAddress?.ToString());

            // 获取用户角色和声明
            var roles = await _userService.GetRolesAsync(user.Id);
            var claims = await _userService.GetClaimsAsync(user.Id);

            // 创建身份标识
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // 添加用户声明
            identity.SetClaim(Claims.Subject, user.Sub);
            identity.SetClaim(Claims.Email, user.Email);
            identity.SetClaim(Claims.Name, user.Name ?? user.UserName);
            identity.SetClaim(Claims.PreferredUsername, user.UserName);

            // 添加角色声明
            foreach (var role in roles)
            {
                identity.SetClaim(Claims.Role, role);
            }

            // 添加自定义声明
            foreach (var claim in claims)
            {
                identity.SetClaim(claim.Type, claim.Value);
            }

            // 设置作用域
            var scopes = request.GetScopes().ToList();
            var allowedScopes = new[] { Scopes.OpenId, Scopes.Email, Scopes.Profile, Scopes.Roles }.Intersect(scopes);
            identity.SetScopes(allowedScopes);

            // 设置资源
            identity.SetResources(await GetScopeResourcesAsync(allowedScopes));
            identity.SetDestinations(GetDestinations);

            _logger.LogInformation("密码模式: 用户 {Username} 登录成功, Scopes={Scopes}",
                request.Username, string.Join(",", allowedScopes));

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        /// <summary>
        /// 处理刷新令牌授权 (refresh_token)
        /// </summary>
        private async Task<IActionResult> HandleRefreshTokenAsync(OpenIddictRequest request)
        {
            if (!request.IsRefreshTokenGrantType())
            {
                _logger.LogWarning("不支持的授权类型: {GrantType}", request.GrantType);
                throw new NotImplementedException("The specified grant type is not implemented.");
            }

            // 创建身份标识
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // 使用 client_id 作为 subject
            identity.SetClaim(Claims.Subject, request.ClientId);
            identity.SetClaim(Claims.Name, request.ClientId);

            // 设置作用域
            var scopes = request.GetScopes().ToList();
            identity.SetScopes(scopes);
            identity.SetResources(await GetScopeResourcesAsync(scopes));
            identity.SetDestinations(GetDestinations);

            _logger.LogInformation("刷新令牌: ClientId={ClientId}, Scopes={Scopes}",
                request.ClientId, scopes.Count == 0 ? "none" : string.Join(",", scopes));

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        #region 待实现授权类型

        private async Task<IActionResult> HandleSmsCodeAsync(OpenIddictRequest request)
        {
            _logger.LogWarning("短信验证码授权尚未实现");
            throw new NotImplementedException("SMS code grant type is not implemented yet.");
        }

        private async Task<IActionResult> HandleWeChatAsync(OpenIddictRequest request)
        {
            _logger.LogWarning("微信授权尚未实现");
            throw new NotImplementedException("WeChat grant type is not implemented yet.");
        }

        private async Task<IActionResult> HandleQQAsync(OpenIddictRequest request)
        {
            _logger.LogWarning("QQ授权尚未实现");
            throw new NotImplementedException("QQ grant type is not implemented yet.");
        }

        private async Task<IActionResult> HandleBiometricAsync(OpenIddictRequest request)
        {
            _logger.LogWarning("生物识别授权尚未实现");
            throw new NotImplementedException("Biometric grant type is not implemented yet.");
        }

        #endregion

        #endregion

        #region 辅助方法

        /// <summary>
        /// 获取作用域关联的资源列表
        /// </summary>
        private async Task<IEnumerable<string>> GetScopeResourcesAsync(IEnumerable<string> scopes)
        {
            var resources = new HashSet<string>();
            foreach (var scopeName in scopes)
            {
                var scope = await _scopeService.GetByNameAsync(scopeName);
                if (scope != null && scope.Resources != null)
                {
                    foreach (var resource in scope.Resources)
                    {
                        resources.Add(resource);
                    }
                }
            }
            return resources;
        }

        /// <summary>
        /// 设置声明的目标（哪些令牌包含该声明）
        /// </summary>
        private static IEnumerable<string> GetDestinations(Claim claim)
        {
            switch (claim.Type)
            {
                case Claims.Name:
                case Claims.PreferredUsername:
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

                case "AspNet.Identity.SecurityStamp":
                    yield break;

                default:
                    yield return Destinations.AccessToken;
                    yield break;
            }
        }

        #endregion
    }
}
