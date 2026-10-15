namespace OpenFindBearings.Identity.Extensions;

/// <summary>
/// 额外 scope 定义（名称 + 资源受众列表），供扩展模块注册。
/// </summary>
/// <param name="Name">scope 名（如 api:sync）</param>
/// <param name="Resources">该 scope 允许的资源受众（如 openfindbearings-api）</param>
public record ExtraScopeDefinition(string Name, IReadOnlyList<string> Resources);

/// <summary>
/// Identity 扩展点（v2.18.0 通用扩展机制）。
/// 开源基座只识别"扩展"这一通用概念、不含任何具体业务；闭源在同项目内新增实现类即可被
/// <see cref="IdentityExtensionLoader"/> 自动发现，注册额外受众资源/额外 scope/给既有 scope 追加资源。
/// 目的：闭源只做加法（新增文件），开源不再为闭源预留具体服务的受众/scope 占位，双方永不改同一共享文件。
/// </summary>
public interface IIdentityExtension
{
    /// <summary>
    /// 额外受众/资源标识符（进入受众目录与 scope 资源；如闭源扩展资源）。无则空集合。
    /// </summary>
    IEnumerable<string> AdditionalApiResources();

    /// <summary>
    /// 额外 scope 定义（如闭源 api:sync）。无则空集合。
    /// </summary>
    IEnumerable<ExtraScopeDefinition> AdditionalScopes();

    /// <summary>
    /// 给既有 scope 追加资源（scope 名 → 追加的资源标识符；如闭源给 api:admin 追加 扩展资源）。无则空集合。
    /// </summary>
    IEnumerable<(string ScopeName, string Resource)> AdditionalScopeResources();
}