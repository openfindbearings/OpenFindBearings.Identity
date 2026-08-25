using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OpenFindBearings.Identity.Constants;
using OpenFindBearings.Identity.Models.Entities;
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
        private readonly UserManager<OidcUser> _userManager;
        private readonly SignInManager<OidcUser> _signInManager;
        private readonly ITenantResolver _tenantResolver;
        private readonly ISmsCodeService _smsCodeService;
        private readonly IConfiguration _configuration;
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly ILogger<AuthorizationController> _logger;

        public AuthorizationController(
            IUserService userService,
            IClientService clientService,
            IScopeService scopeService,
            UserManager<OidcUser> userManager,
            SignInManager<OidcUser> signInManager,
            ITenantResolver tenantResolver,
            ISmsCodeService smsCodeService,
            IConfiguration configuration,
            IOpenIddictApplicationManager applicationManager,
            ILogger<AuthorizationController> logger)
        {
            _userService = userService;
            _clientService = clientService;
            _scopeService = scopeService;
            _userManager = userManager;
            _signInManager = signInManager;
            _tenantResolver = tenantResolver;
            _smsCodeService = smsCodeService;
            _configuration = configuration;
            _applicationManager = applicationManager;
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

            // 验证客户端属于当前租户
            var authorizClientCheck = await ValidateClientTenantAsync(request);
            if (authorizClientCheck != null) return authorizClientCheck;

            // 验证请求 scope 属于当前租户
            var authorizScopeCheck = await ValidateScopesTenantAsync(request);
            if (authorizScopeCheck != null) return authorizScopeCheck;

            // 检查用户是否已登录
            var authResult = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
            if (authResult is { Succeeded: true })
            {
                // 用户已认证，检查租户是否匹配
                var tenantInfo = await _tenantResolver.ResolveAsync();
                if (tenantInfo.TenantId.HasValue)
                {
                    var userIdClaim = authResult.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
                    if (!string.IsNullOrEmpty(userIdClaim) && Guid.TryParse(userIdClaim, out var userId))
                    {
                        var user = await _userService.GetByIdAsync(userId);
                        if (user != null && user.TenantId != tenantInfo.TenantId.Value)
                        {
                            // 租户不匹配：跳转登录页，用户重新登录时自然覆盖旧 cookie
                            _logger.LogInformation("授权请求: 当前用户租户 {UserTenant} 与请求租户 {ReqTenant} 不匹配，跳转登录页",
                                user.TenantId, tenantInfo.TenantId);
                            return Challenge(new AuthenticationProperties
                            {
                                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(Request.HasFormContentType ? Request.Form : Request.Query)
                            });
                        }
                    }
                }

                return await IssueAuthorizationCodeAsync(request, authResult.Principal);
            }

            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(Request.HasFormContentType ? Request.Form : Request.Query)
            });
        }

        /// <summary>
        /// 授予授权码（自动同意）
        /// </summary>
        private async Task<IActionResult> IssueAuthorizationCodeAsync(OpenIddictRequest request, ClaimsPrincipal? authenticatedPrincipal = null)
        {
            var principal = authenticatedPrincipal ?? User;

            // 从 Identity cookie 主体验证中获取用户 ID
            var userIdStr = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userIdStr) || !Guid.TryParse(userIdStr, out var userId))
            {
                _logger.LogWarning("授权码: Cookie 中缺少 NameIdentifier, Claims={Claims}",
                    string.Join(", ", principal.Claims.Select(c => $"{c.Type}")));
                return Forbid(
                    new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "No NameIdentifier claim in cookie."
                    }),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var user = await _userService.GetByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("授权码: 用户不存在 UserId={UserId}", userId);
                return Forbid(
                    new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "User not found."
                    }),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 校验租户隔离：请求中的 realm/tenant_id 必须匹配用户归属
            var tenantInfo = await _tenantResolver.ResolveAsync();
            if (tenantInfo.TenantId.HasValue && user.TenantId != tenantInfo.TenantId.Value)
            {
                _logger.LogWarning("授权码: 租户不匹配, UserTenantId={UserTenantId}, RequestTenantId={RequestTenantId}",
                    user.TenantId, tenantInfo.TenantId);
                return Forbid(
                    new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Tenant mismatch."
                    }),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 加载 OidcUser 实体，通过 SignInManager 创建完整身份标识
            var oidcUser = await _userManager.FindByIdAsync(user.Id.ToString());
            if (oidcUser == null)
            {
                _logger.LogWarning("授权码: 无法加载 OidcUser 实体 {UserId}", user.Id);
                return Forbid(
                    new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "OidcUser entity not found."
                    }),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 使用 ABP 模式：通过 SignInManager 创建完整的身份标识
            var userPrincipal = await _signInManager.CreateUserPrincipalAsync(oidcUser);
            var identity = userPrincipal.Identities.First();

            // 确保 OpenIddict 需要的 Subject(sub) 声明存在
            if (!identity.HasClaim(Claims.Subject))
                identity.AddClaim(new Claim(Claims.Subject, user.Sub));

            identity.AddClaim(new Claim("tenant_id", user.TenantId?.ToString() ?? ""));

            // 从 authorize 请求获取 device_id 并写入授权码 principal
            var deviceId = Request.Query["device_id"].FirstOrDefault();
            if (!string.IsNullOrEmpty(deviceId))
                identity.AddClaim(new Claim("device_id", deviceId));

            var scopes = request.GetScopes().ToList();
            userPrincipal.SetScopes(scopes);
            userPrincipal.SetResources(await GetScopeResourcesAsync(scopes));
            userPrincipal.SetDestinations(GetDestinations);

            _logger.LogInformation("授权码: 用户 {Username} 授权成功, ClientId={ClientId}",
                user.UserName, request.ClientId);

            return SignIn(userPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        #region 授权类型处理

        /// <summary>
        /// 处理授权码授权 (authorization_code)
        /// 授权码已在 /connect/authorize 端点签发，此处从已存储的授权中恢复用户身份并签发 token
        /// </summary>
        private async Task<IActionResult> HandleAuthorizationCodeAsync(OpenIddictRequest request)
        {
            // 验证客户端属于当前租户
            var authCodeClientCheck = await ValidateClientTenantAsync(request);
            if (authCodeClientCheck != null) return authCodeClientCheck;

            var authCodeScopeCheck = await ValidateScopesTenantAsync(request);
            if (authCodeScopeCheck != null) return authCodeScopeCheck;

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

            // 校验租户隔离：请求中的 realm/tenant_id 必须匹配用户归属
            var tenantInfo = await _tenantResolver.ResolveAsync();
            if (tenantInfo.TenantId.HasValue && user.TenantId != tenantInfo.TenantId.Value)
            {
                _logger.LogWarning("授权码令牌交换: 租户不匹配, UserTenantId={UserTenantId}, RequestTenantId={RequestTenantId}",
                    user.TenantId, tenantInfo.TenantId);
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The authorization code is no longer valid."
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

            // 添加 OIDC Profile 声明
            if (!string.IsNullOrEmpty(user.PhoneNumber))
                identity.SetClaim("phone_number", user.PhoneNumber);
            if (!string.IsNullOrEmpty(user.GivenName))
                identity.SetClaim(Claims.GivenName, user.GivenName);
            if (!string.IsNullOrEmpty(user.FamilyName))
                identity.SetClaim(Claims.FamilyName, user.FamilyName);
            if (!string.IsNullOrEmpty(user.Nickname))
                identity.SetClaim("nickname", user.Nickname);
            if (!string.IsNullOrEmpty(user.Gender))
                identity.SetClaim("gender", user.Gender);
            if (user.Birthdate.HasValue)
                identity.SetClaim("birthdate", user.Birthdate.Value.ToString("yyyy-MM-dd"));
            if (!string.IsNullOrEmpty(user.Locale))
                identity.SetClaim("locale", user.Locale);
            if (!string.IsNullOrEmpty(user.ZoneInfo))
                identity.SetClaim("zoneinfo", user.ZoneInfo);

            // 添加租户声明
            identity.SetClaim("tenant_id", user.TenantId?.ToString() ?? "");

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

            // 设置作用域（scopes 由 OpenIddict 前置校验过滤，handler 内无需再过滤）
            var scopes = request.GetScopes().ToList();
            identity.SetScopes(scopes);
            identity.SetResources(await GetScopeResourcesAsync(scopes));
            identity.SetDestinations(GetDestinations);

            _logger.LogInformation("授权码模式: 用户 {Username} Token 交换成功, Scopes={Scopes}",
                user.UserName, string.Join(",", scopes));

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

            // 验证客户端属于当前租户
            var ccClientCheck = await ValidateClientTenantAsync(request);
            if (ccClientCheck != null) return ccClientCheck;

            var ccScopeCheck = await ValidateScopesTenantAsync(request);
            if (ccScopeCheck != null) return ccScopeCheck;

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

            // 添加租户声明（M2M 客户端若有租户上下文的请求参数）
            var clientTenantInfo = await _tenantResolver.ResolveAsync();
            if (clientTenantInfo.TenantId.HasValue)
            {
                identity.SetClaim("tenant_id", clientTenantInfo.TenantId.Value.ToString());
            }

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

            // 验证客户端属于当前租户
            var pwClientCheck = await ValidateClientTenantAsync(request);
            if (pwClientCheck != null) return pwClientCheck;

            var pwScopeCheck = await ValidateScopesTenantAsync(request);
            if (pwScopeCheck != null) return pwScopeCheck;

            // 解析租户并查找用户
            var tenantInfo = await _tenantResolver.ResolveAsync();
            if (tenantInfo.TenantId == null)
            {
                _logger.LogWarning("密码模式: 请求缺少 tenant_id/realm 参数 {Username}", request.Username);
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var user = await _userService.GetByUsernameAsync(request.Username!, tenantInfo.TenantId.Value);
            if (user == null)
            {
                _logger.LogWarning("密码模式: 用户不存在 {Username}", request.Username);
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 用户已在租户范围内查询，无需二次校验

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

            // 添加 OIDC Profile 声明（为 Admin Profile 页面提供完整用户信息）
            if (!string.IsNullOrEmpty(user.PhoneNumber))
                identity.SetClaim("phone_number", user.PhoneNumber);
            if (!string.IsNullOrEmpty(user.GivenName))
                identity.SetClaim(Claims.GivenName, user.GivenName);
            if (!string.IsNullOrEmpty(user.FamilyName))
                identity.SetClaim(Claims.FamilyName, user.FamilyName);
            if (!string.IsNullOrEmpty(user.Nickname))
                identity.SetClaim("nickname", user.Nickname);
            if (!string.IsNullOrEmpty(user.Gender))
                identity.SetClaim("gender", user.Gender);
            if (user.Birthdate.HasValue)
                identity.SetClaim("birthdate", user.Birthdate.Value.ToString("yyyy-MM-dd"));
            if (!string.IsNullOrEmpty(user.Locale))
                identity.SetClaim("locale", user.Locale);
            if (!string.IsNullOrEmpty(user.ZoneInfo))
                identity.SetClaim("zoneinfo", user.ZoneInfo);

            // 添加租户声明
            identity.SetClaim("tenant_id", user.TenantId?.ToString() ?? "");

            // 添加设备标识（用于刷新令牌时校验设备绑定）
            var deviceId = request.GetParameter("device_id")?.ToString();
            if (!string.IsNullOrEmpty(deviceId))
                identity.SetClaim("device_id", deviceId);

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

            // 设置作用域（scopes 由 OpenIddict 前置校验过滤，handler 内无需再过滤）
            var scopes = request.GetScopes().ToList();
            identity.SetScopes(scopes);

            // 设置资源
            identity.SetResources(await GetScopeResourcesAsync(scopes));
            identity.SetDestinations(GetDestinations);

            _logger.LogInformation("密码模式: 用户 {Username} 登录成功, Scopes={Scopes}",
                request.Username, string.Join(",", scopes));

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

            // 验证客户端属于当前租户
            var rtClientCheck = await ValidateClientTenantAsync(request);
            if (rtClientCheck != null) return rtClientCheck;

            var rtScopeCheck = await ValidateScopesTenantAsync(request);
            if (rtScopeCheck != null) return rtScopeCheck;

            // 从 OpenIddict 中间件获取原始授权的用户身份
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var originalClaims = result?.Principal?.Claims ?? Enumerable.Empty<Claim>();

            // 从 Subject 获取用户 ID，加载完整用户信息
            var subject = result?.Principal?.FindFirst(Claims.Subject)?.Value;
            Guid? userId = null;
            OidcUser? user = null;
            if (!string.IsNullOrEmpty(subject) && Guid.TryParse(subject, out var uid))
            {
                userId = uid;
                user = await _userManager.FindByIdAsync(subject);
            }

            // 验证租户：请求中的 realm/tenant_id 必须与用户的 TenantId 一致
            if (user != null)
            {
                var tenantInfo = await _tenantResolver.ResolveAsync();
                if (tenantInfo.TenantId.HasValue && user.TenantId != tenantInfo.TenantId.Value)
                {
                    _logger.LogWarning("刷新令牌: 租户不匹配 UserId={UserId}, UserTenant={UserTenant}, ReqTenant={ReqTenant}",
                        userId, user.TenantId, tenantInfo.TenantId);
                    return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Token refresh failed."
                    }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }
            }

            // 设备绑定校验：如果原始 token 有 device_id，刷新请求也必须携带且一致
            var originalDeviceId = originalClaims.FirstOrDefault(c => c.Type == "device_id")?.Value;
            var requestDeviceId = request.GetParameter("device_id")?.ToString();
            if (!string.IsNullOrEmpty(originalDeviceId))
            {
                if (string.IsNullOrEmpty(requestDeviceId) || originalDeviceId != requestDeviceId)
                {
                    _logger.LogWarning("刷新令牌: device_id 不匹配, Original={Original}, Request={Request}",
                        originalDeviceId, requestDeviceId ?? "(空)");
                    return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Token refresh failed: device mismatch."
                    }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }
            }

            // 创建身份标识
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            if (user != null)
            {
                // 使用用户信息重建完整声明
                identity.SetClaim(Claims.Subject, user.Sub);
                identity.SetClaim(Claims.Email, user.Email);
                identity.SetClaim(Claims.Name, user.Name ?? user.UserName);
                identity.SetClaim(Claims.PreferredUsername, user.UserName);

                if (!string.IsNullOrEmpty(user.PhoneNumber))
                    identity.SetClaim("phone_number", user.PhoneNumber);
                if (!string.IsNullOrEmpty(user.GivenName))
                    identity.SetClaim(Claims.GivenName, user.GivenName);
                if (!string.IsNullOrEmpty(user.FamilyName))
                    identity.SetClaim(Claims.FamilyName, user.FamilyName);
                if (!string.IsNullOrEmpty(user.Nickname))
                    identity.SetClaim("nickname", user.Nickname);
                if (!string.IsNullOrEmpty(user.Gender))
                    identity.SetClaim("gender", user.Gender);
                if (user.Birthdate.HasValue)
                    identity.SetClaim("birthdate", user.Birthdate.Value.ToString("yyyy-MM-dd"));
                if (!string.IsNullOrEmpty(user.Locale))
                    identity.SetClaim("locale", user.Locale);
                if (!string.IsNullOrEmpty(user.ZoneInfo))
                    identity.SetClaim("zoneinfo", user.ZoneInfo);

                identity.SetClaim("tenant_id", user.TenantId.ToString());

                // 传递设备标识到新 token
                if (!string.IsNullOrEmpty(originalDeviceId))
                    identity.SetClaim("device_id", originalDeviceId);

                // 加载角色声明
                var roles = await _userService.GetRolesAsync(user.Id);
                foreach (var role in roles)
                {
                    identity.SetClaim(Claims.Role, role);
                }
            }
            else
            {
                // 回退：使用 client_id 作为 subject（M2M 场景）
                identity.SetClaim(Claims.Subject, request.ClientId);
                identity.SetClaim(Claims.Name, request.ClientId);

                // 从原始授权中恢复 tenant_id（如果有）
                var tenantId = originalClaims.FirstOrDefault(c => c.Type == "tenant_id")?.Value;
                if (!string.IsNullOrEmpty(tenantId))
                {
                    identity.SetClaim("tenant_id", tenantId);
                }

                // 从原始授权中恢复 device_id（如果有）
                if (!string.IsNullOrEmpty(originalDeviceId))
                    identity.SetClaim("device_id", originalDeviceId);
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

        private async Task<IActionResult> HandleSmsCodeAsync(OpenIddictRequest request)
        {
            if (request.GrantType != GrantTypeConstants.Sms)
            {
                _logger.LogWarning("不支持的授权类型: {GrantType}", request.GrantType);
                throw new NotImplementedException("The specified grant type is not implemented.");
            }

            // 验证客户端属于当前租户
            var smsClientCheck = await ValidateClientTenantAsync(request);
            if (smsClientCheck != null) return smsClientCheck;

            var smsScopeCheck = await ValidateScopesTenantAsync(request);
            if (smsScopeCheck != null) return smsScopeCheck;

            // 获取手机号和验证码
            var phone = request.GetParameter("phone")?.ToString();
            var code = request.GetParameter("code")?.ToString();

            if (string.IsNullOrEmpty(phone) || string.IsNullOrEmpty(code))
            {
                _logger.LogWarning("SMS模式: 缺少手机号或验证码");
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Invalid phone or code."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 验证验证码
            var isValid = await _smsCodeService.ValidateAsync(phone, code, SmsCodeTypeConstants.Login);
            if (!isValid)
            {
                _logger.LogWarning("SMS模式: 验证码无效 Phone={Phone}", phone);
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Invalid verification code."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 解析租户
            var tenantInfo = await _tenantResolver.ResolveAsync();
            if (tenantInfo.TenantId == null)
            {
                _logger.LogWarning("SMS模式: 缺少租户信息");
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Missing tenant information."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 查找或创建用户
            var userDto = await _userService.GetByPhoneNumberAsync(phone, tenantInfo.TenantId.Value);
            OidcUser user;

            if (userDto == null)
            {
                user = OidcUser.Create(
                    userName: phone,
                    email: null,
                    tenantId: tenantInfo.TenantId,
                    phoneNumber: phone,
                    name: phone
                );

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    var errors = string.Join(", ", createResult.Errors.Select(e => e.Description));
                    _logger.LogError("SMS模式: 自动创建用户失败 Phone={Phone}, Errors={Errors}", phone, errors);
                    return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ServerError,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Failed to create user."
                    }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                _logger.LogInformation("SMS模式: 自动创建用户成功 Phone={Phone}, UserId={UserId}", phone, user.Id);
            }
            else
            {
                user = (await _userManager.FindByIdAsync(userDto.Id.ToString()))!;
                if (user == null)
                {
                    _logger.LogWarning("SMS模式: 无法加载用户 Phone={Phone}", phone);
                    return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "User not found."
                    }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }
            }

            // 检查用户是否可以登录
            var canLogin = await _userService.CheckCanLoginAsync(user.Id);
            if (!canLogin)
            {
                _logger.LogWarning("SMS模式: 用户无法登录 Phone={Phone}", phone);
                await _userService.RecordLoginFailureAsync(user.Id);
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The account is not available."
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            await _userService.RecordLoginSuccessAsync(user.Id, HttpContext.Connection.RemoteIpAddress?.ToString());

            // 创建身份标识
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // 添加用户声明
            identity.SetClaim(Claims.Subject, user.Sub);
            if (!string.IsNullOrEmpty(user.PhoneNumber))
                identity.SetClaim("phone_number", user.PhoneNumber);
            identity.SetClaim(Claims.Name, user.Name ?? user.UserName);
            identity.SetClaim(Claims.PreferredUsername, user.UserName);

            // 添加租户声明
            identity.SetClaim("tenant_id", user.TenantId?.ToString() ?? "");

            // 添加设备标识（用于刷新令牌时校验设备绑定）
            var deviceId = request.GetParameter("device_id")?.ToString();
            if (!string.IsNullOrEmpty(deviceId))
                identity.SetClaim("device_id", deviceId);

            // 获取角色声明
            var roles = await _userService.GetRolesAsync(user.Id);
            foreach (var role in roles)
            {
                identity.SetClaim(Claims.Role, role);
            }

            // 设置作用域
            var scopes = request.GetScopes().ToList();
            identity.SetScopes(scopes);
            identity.SetResources(await GetScopeResourcesAsync(scopes));
            identity.SetDestinations(GetDestinations);

            _logger.LogInformation("SMS模式: 用户 {Phone} 登录成功, Scopes={Scopes}",
                phone, scopes.Count == 0 ? "none" : string.Join(",", scopes));

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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

        #region 辅助方法

        /// <summary>
        /// UserInfo 端点 - 返回当前用户信息，包含租户上下文
        /// </summary>
        [HttpGet("~/connect/userinfo")]
        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        public async Task<IActionResult> Userinfo()
        {
            var subject = User.FindFirst(Claims.Subject)?.Value;
            if (string.IsNullOrEmpty(subject))
            {
                return Challenge(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var user = await _userManager.FindByIdAsync(subject);
            if (user == null)
            {
                return NotFound();
            }

            var claims = new Dictionary<string, object?>
            {
                [Claims.Subject] = user.Sub,
                [Claims.Name] = user.Name ?? user.UserName
            };

            if (!string.IsNullOrEmpty(user.Email))
                claims[Claims.Email] = user.Email;
            if (!string.IsNullOrEmpty(user.PhoneNumber))
                claims["phone_number"] = user.PhoneNumber;

            // 从 access_token 中读取 tenant_id，确保与用户实际 TenantId 一致
            var tokenTenantId = User.FindFirst("tenant_id")?.Value;
            if (!string.IsNullOrEmpty(tokenTenantId) && Guid.TryParse(tokenTenantId, out var tid))
            {
                if (user.TenantId != tid)
                {
                    _logger.LogWarning("UserInfo: 令牌中的租户 {TokenTenant} 与用户 {ActualTenant} 不匹配", tid, user.TenantId);
                    return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }
                claims["tenant_id"] = tid.ToString();
            }
            else if (user.TenantId.HasValue)
            {
                claims["tenant_id"] = user.TenantId.Value.ToString();
            }

            if (User.HasScope(Scopes.Email))
            {
                claims[Claims.EmailVerified] = user.EmailConfirmed;
            }

            if (User.HasScope(Scopes.Profile))
            {
                if (!string.IsNullOrEmpty(user.GivenName))
                    claims[Claims.GivenName] = user.GivenName;
                if (!string.IsNullOrEmpty(user.FamilyName))
                    claims[Claims.FamilyName] = user.FamilyName;
                if (user.Birthdate.HasValue)
                    claims["birthdate"] = user.Birthdate.Value.ToString("yyyy-MM-dd");
            }

            return Ok(claims);
        }

        /// <summary>
        /// OIDC 结束会话端点（RP-Initiated Logout）
        /// </summary>
        [HttpGet("~/connect/logout")]
        public async Task<IActionResult> EndSession(string? post_logout_redirect_uri = null)
        {
            await _signInManager.SignOutAsync();

            // 标准 OIDC RP-Initiated Logout：精确匹配已注册客户端的 PostLogoutRedirectUris
            if (!string.IsNullOrEmpty(post_logout_redirect_uri))
            {
                var isAllowed = await IsAllowedLogoutRedirectAsync(post_logout_redirect_uri);
                if (isAllowed)
                {
                    _logger.LogInformation("结束会话，重定向至: {Uri}", post_logout_redirect_uri);
                    return Redirect(post_logout_redirect_uri);
                }
                _logger.LogWarning("注销回调地址未在客户端 PostLogoutRedirectUris 中注册: {Uri}", post_logout_redirect_uri);
            }

            return Redirect("~/");
        }

        [HttpPost("~/connect/logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EndSessionPost()
        {
            await _signInManager.SignOutAsync();
            return Redirect("~/");
        }

        /// <summary>
        /// 校验注销回调地址是否精确匹配已注册客户端的 PostLogoutRedirectUris
        /// </summary>
        private async Task<bool> IsAllowedLogoutRedirectAsync(string redirectUri)
        {
            await foreach (var application in _applicationManager.ListAsync())
            {
                var postLogoutUris = await _applicationManager.GetPostLogoutRedirectUrisAsync(application);
                if (postLogoutUris.Any(uri => string.Equals(redirectUri, uri, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
            return false;
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

    #region 租户隔离辅助方法

    private async Task<IActionResult?> ValidateClientTenantAsync(OpenIddictRequest request)
    {
        if (string.IsNullOrEmpty(request.ClientId))
            return null;

        var tenantInfo = await _tenantResolver.ResolveAsync();
        if (tenantInfo.TenantId == null)
            return null;

        if (!await _clientService.IsClientInTenantAsync(request.ClientId, tenantInfo.TenantId))
        {
            _logger.LogWarning("客户端 {ClientId} 不属于当前租户 {TenantId}",
                request.ClientId, tenantInfo.TenantId);
            return BadRequest("Invalid client_id for this tenant");
        }

        return null;
    }

    private async Task<IActionResult?> ValidateScopesTenantAsync(OpenIddictRequest request)
    {
        if (string.IsNullOrEmpty(request.Scope))
            return null;

        var tenantInfo = await _tenantResolver.ResolveAsync();
        if (tenantInfo.TenantId == null)
            return null;

        var standardScopes = new HashSet<string> { "openid", "profile", "email", "phone", "address", "roles" };
        var requestedScopes = request.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        foreach (var scope in requestedScopes)
        {
            if (standardScopes.Contains(scope))
                continue;

            if (!await _scopeService.IsScopeInTenantAsync(scope, tenantInfo.TenantId))
            {
                _logger.LogWarning("Scope {Scope} 不属于当前租户 {TenantId}", scope, tenantInfo.TenantId);
                return BadRequest($"Invalid scope '{scope}' for this tenant");
            }
        }

        return null;
    }

    #endregion
}
}
