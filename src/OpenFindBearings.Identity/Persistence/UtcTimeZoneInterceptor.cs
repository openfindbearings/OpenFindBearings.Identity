using Microsoft.EntityFrameworkCore.Diagnostics;
using System.Data.Common;

namespace OpenFindBearings.Identity.Persistence
{
    /// <summary>
    /// PostgreSQL 时区拦截器：每个连接打开后执行 SET timezone='UTC'，
    /// 确保 DateTime.UtcNow 写入 timestamptz 列后读出仍为 UTC，不受服务器时区影响。
    /// </summary>
    public class UtcTimeZoneInterceptor : DbConnectionInterceptor
    {
        /// <summary>
        /// 同步连接打开后设置时区为 UTC
        /// </summary>
        public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
        {
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SET timezone='UTC'";
            cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// 异步连接打开后设置时区为 UTC
        /// </summary>
        public override async Task ConnectionOpenedAsync(
            DbConnection connection,
            ConnectionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SET timezone='UTC'";
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
    }
}
