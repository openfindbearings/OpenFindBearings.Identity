using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
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
                GrantTypeConstants.AuthorizationCode => await HandleAuthorizationCodeAsync(request),
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

        /// <summary>
        /// 授权端点 - 处理授权码请求（Admin 登录用）
        /// </summary>
        [HttpGet("~/connect/authorize")]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest()
                ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            _logger.LogInformation("收到授权请求: ClientId={ClientId}, RedirectUri={RedirectUri}",
                request.ClientId, request.RedirectUri);

            // 验证客户端是否存在
            var client = await _clientService.GetByClientIdAsync(request.ClientId!);
            if (client == null)
            {
                _logger.LogWarning("授权请求: 客户端不存在 {ClientId}", request.ClientId);
                return BadRequest("Invalid client_id");
            }

            // 检查用户是否已登录
            if (!User.Identity?.IsAuthenticated ?? true)
            {
                // 未登录，跳转到登录页，保留完整原始请求 URL（含所有 query 参数）
                var returnUrl = $"{Request.Path}{Request.QueryString}";
                return Redirect($"/connect/authorize/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
            }

            // Implicit 模式：自动授予授权码
            return await IssueAuthorizationCodeAsync(request);
        }

        /// <summary>
        /// 授予授权码（自动同意）
        /// </summary>
        private async Task<IActionResult> IssueAuthorizationCodeAsync(OpenIddictRequest request)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Forbid("Authentication cookie is invalid.");
            }

            var user = await _userService.GetByIdAsync(userId);
            if (user == null)
            {
                return Forbid("Authentication cookie is invalid.");
            }

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

            // 添加租户声明
            identity.SetClaim("tenant_id", user.TenantId.ToString());

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
            identity.SetResources(await GetScopeResourcesAsync(allowedScopes));
            identity.SetDestinations(GetDestinations);

            _logger.LogInformation("授权码: 用户 {Username} 授权成功, ClientId={ClientId}",
                user.UserName, request.ClientId);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        #region 授权类型处理

        /// <summary>
        /// 处理授权码授权 (authorization_code)
        /// 授权码已在 /connect/authorize 端点签发，此处从已存储的授权中恢复用户身份并签发 token
        /// </summary>
        private async Task<IActionResult> HandleAuthorizationCodeAsync(OpenIddictRequest request)
        {
            // 从 OpenIddict 中间件获取授权码关联的用户身份
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (result?.Principal == null)
            {
                _logger.LogWarning("授权码模式: 无法从授权码中恢复用户身份");
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The authorization code is no longer valid."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 从 Subject 获取用户 ID，加载完整用户信息
            var subject = result.Principal.FindFirst(Claims.Subject)?.Value;
            if (string.IsNullOrEmpty(subject))
            {
                _logger.LogWarning("授权码模式: 授权码中缺少 Subject 声明");
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The authorization code is invalid."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var user = await _userService.GetByIdAsync(Guid.Parse(subject));
            if (user == null)
            {
                _logger.LogWarning("授权码模式: 用户不存在 Subject={Subject}", subject);
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user account is no longer available."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 检查用户是否可以登录
            var canLogin = await _userService.CheckCanLoginAsync(user.Id);
            if (!canLogin)
            {
                _logger.LogWarning("授权码模式: 用户无法登录 UserId={UserId}", user.Id);
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user account is no longer available."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 获取用户角色和声明
            var roles = await _userService.GetRolesAsync(user.Id);
            var claims = await _userService.GetClaimsAsync(user.Id);

            // 创建新的身份标识
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // 添加用户声明
            identity.SetClaim(Claims.Subject, user.Sub);
            identity.SetClaim(Claims.Email, user.Email);
            identity.SetClaim(Claims.Name, user.Name ?? user.UserName);
            identity.SetClaim(Claims.PreferredUsername, user.UserName);

            // 添加租户声明
            identity.SetClaim("tenant_id", user.TenantId.ToString());

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
            identity.SetResources(await GetScopeResourcesAsync(allowedScopes));
            identity.SetDestinations(GetDestinations);

            _logger.LogInformation("授权码模式: 用户 {Username} Token 交换成功, Scopes={Scopes}",
                user.UserName, string.Join(",", allowedScopes));

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

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

            // 添加租户声明
            identity.SetClaim("tenant_id", user.TenantId.ToString());

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

            // 从 OpenIddict 中间件获取原始授权的用户身份
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var originalClaims = result?.Principal?.Claims ?? Enumerable.Empty<Claim>();

            // 创建身份标识
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // 使用 client_id 作为 subject
            identity.SetClaim(Claims.Subject, request.ClientId);
            identity.SetClaim(Claims.Name, request.ClientId);

            // 从原始授权中恢复 tenant_id（如果有）
            var tenantId = originalClaims.FirstOrDefault(c => c.Type == "tenant_id")?.Value;
            if (!string.IsNullOrEmpty(tenantId))
            {
                identity.SetClaim("tenant_id", tenantId);
            }

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
        /// 登录页面（Admin OAuth 流程）
        /// </summary>
        [HttpGet("~/connect/authorize/login")]
        public IActionResult Login(string returnUrl = "/")
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        /// <summary>
        /// 处理登录提交
        /// </summary>
        [HttpPost("~/connect/authorize/login")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginSubmit(string username, string password, string returnUrl = "/")
        {
            // 验证用户名和密码
            var user = await _userService.GetByUsernameAsync(username);
            if (user == null)
            {
                ViewBag.Error = "用户名或密码错误";
                ViewBag.ReturnUrl = returnUrl;
                return View("Login");
            }

            // 检查用户是否可以登录
            var canLogin = await _userService.CheckCanLoginAsync(user.Id);
            if (!canLogin)
            {
                ViewBag.Error = "账户不可用";
                ViewBag.ReturnUrl = returnUrl;
                return View("Login");
            }

            // 验证密码
            var isValidPassword = await _userService.CheckPasswordAsync(user.Id, password);
            if (!isValidPassword)
            {
                await _userService.RecordLoginFailureAsync(user.Id);
                ViewBag.Error = "用户名或密码错误";
                ViewBag.ReturnUrl = returnUrl;
                return View("Login");
            }

            // 记录登录成功
            await _userService.RecordLoginSuccessAsync(user.Id, HttpContext.Connection.RemoteIpAddress?.ToString());

            // 创建 Cookie 登录（为后续授权端点使用）
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName ?? "")
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

            return Redirect(returnUrl);
        }

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
