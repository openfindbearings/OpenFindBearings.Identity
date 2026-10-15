using System.Reflection;

namespace OpenFindBearings.Identity.Extensions;

/// <summary>
/// Identity 扩展加载器（v2.18.0 通用扩展机制）：反射发现当前 Identity 程序集中所有
/// <see cref="IIdentityExtension"/> 实现。开源基座内无任何实现 = 返回空列表（零副作用）；
/// 闭源在同项目新增实现类即被接入。
/// </summary>
public static class IdentityExtensionLoader
{
    /// <summary>
    /// 发现并实例化所有扩展（无实现 = 空列表）。
    /// </summary>
    /// <returns>扩展列表</returns>
    public static IReadOnlyList<IIdentityExtension> Discover()
    {
        var list = new List<IIdentityExtension>();
        foreach (var type in Assembly.GetExecutingAssembly().GetTypes())
        {
            if (type.IsAbstract || type.IsInterface || !typeof(IIdentityExtension).IsAssignableFrom(type))
                continue;

            if (Activator.CreateInstance(type) is IIdentityExtension ext)
                list.Add(ext);
        }
        return list;
    }

    /// <summary>
    /// 汇总所有扩展贡献的额外受众资源（去重、去空）。
    /// </summary>
    /// <returns>额外受众资源列表（开源无扩展 = 空）</returns>
    public static IReadOnlyList<string> AdditionalApiResources() =>
        Discover()
            .SelectMany(e => e.AdditionalApiResources())
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct()
            .ToList();
}