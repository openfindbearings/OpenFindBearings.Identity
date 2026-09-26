namespace OpenFindBearings.Identity.Services;

/// <summary>
/// 业务时钟（Identity 侧，v2.18.0 时间治理批次）：与 API 项目的 BusinessClock 同构的独立实现。
/// 职责：为"今日短信配额""今日审计计数"这类按天归边逻辑提供统一日界，
/// 修复 UTC 零点切日导致中国用户凌晨 0-8 点动作归入前一天的错位。
/// 约束：DB 存储与写入仍纯 DateTime.UtcNow（全项目规范），本类只定"哪一天"的边界；
/// 因 Identity 是独立解决方案引用不到 API 的 Domain 程序集，故按共享内核模式各自持有一份
/// （偏移配置源不同：API 读 SystemConfigs 表，Identity 读自身 appsettings，默认同为 +8 北京）
/// </summary>
public static class BusinessClock
{
    /// <summary>业务时区偏移（默认北京时间 UTC+8，启动时由 Program.cs 读配置覆盖）</summary>
    private static TimeSpan _businessOffset = TimeSpan.FromHours(8);

    /// <summary>
    /// 配置业务日界偏移。合法范围 -12~+14（全球时区偏移域），越界忽略保留默认
    /// </summary>
    /// <param name="offsetHours">偏移小时数</param>
    public static void Configure(int offsetHours)
    {
        if (offsetHours is >= -12 and <= 14)
        {
            _businessOffset = TimeSpan.FromHours(offsetHours);
        }
    }

    /// <summary>业务日零点对应的 UTC 时刻——DB 范围查询专用（CreatedAt &gt;= TodayUtc 即"业务今天"）</summary>
    public static DateTime TodayUtc => DateTime.UtcNow.Add(_businessOffset).Date - _businessOffset;
}
