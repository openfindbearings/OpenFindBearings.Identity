namespace OpenFindBearings.Identity.Extensions;

/// <summary>
/// 扩展客户端定义：由扩展方贡献、由种子流程注册到 OpenIddict 的 OAuth 客户端。
/// 用途：让扩展能力（如机器对机器调用）拥有自己的客户端，而开源基座不感知具体业务。
/// </summary>
/// <param name="ClientId">客户端标识（机器名，唯一）</param>
/// <param name="ClientSecret">客户端密钥；为空表示公开客户端（无密钥）。密钥必须由调用方从配置或密钥管理系统读取，不得硬编码</param>
/// <param name="DisplayName">显示名（管理台可见）</param>
/// <param name="Scopes">需要申请的 scope 列表（如 api:xxx）</param>
public record ExtraClientDefinition(
    string ClientId,
    string? ClientSecret,
    string DisplayName,
    IReadOnlyList<string> Scopes);

/// <summary>
/// Identity 客户端扩展点（v2.22.0 通用扩展机制）：扩展方实现本接口即可在种子阶段
/// 注册额外 OAuth 客户端，无需改动开源共享文件。
/// 与 <see cref="IIdentityExtension"/> 分离，避免影响已有的资源/scope 扩展实现。
/// </summary>
public interface IIdentityClientExtension
{
    /// <summary>
    /// 额外客户端定义列表；无则返回空集合。密钥由实现方自行从配置读取。
    /// </summary>
    IEnumerable<ExtraClientDefinition> AdditionalClients();
}