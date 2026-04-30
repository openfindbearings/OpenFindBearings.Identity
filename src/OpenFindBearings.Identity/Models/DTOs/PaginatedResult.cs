using Microsoft.EntityFrameworkCore;

namespace OpenFindBearings.Identity.Models.DTOs
{
    public class PaginatedResult<T>
    {
        public IReadOnlyList<T> Items { get; }
        public int PageIndex { get; }
        public int PageSize { get; }
        public int TotalCount { get; }
        public int TotalPages { get; }
        public bool HasPreviousPage => PageIndex > 1;
        public bool HasNextPage => PageIndex < TotalPages;

        // 无参构造函数（用于 ViewModel 初始化）
        public PaginatedResult()
        {
            Items = Array.Empty<T>();
            PageIndex = 1;
            PageSize = 10;
            TotalCount = 0;
            TotalPages = 0;
        }

        // 主要构造函数
        public PaginatedResult(
            IReadOnlyList<T> items,
            int totalCount,  // 显式传入 totalCount
            int pageIndex,
            int pageSize)
        {
            Items = items;
            TotalCount = totalCount;
            PageIndex = pageIndex;
            PageSize = pageSize;
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
        }

        // 便捷构造函数（自动计算 TotalCount，但注意性能）
        public PaginatedResult(
            IReadOnlyList<T> items,
            int pageIndex = 1,
            int pageSize = 10)
        {
            Items = items;
            TotalCount = items.Count;  // 使用 Count 属性
            PageIndex = pageIndex;
            PageSize = pageSize;
            TotalPages = (int)Math.Ceiling(TotalCount / (double)pageSize);
        }

        public static async Task<PaginatedResult<T>> CreateAsync(
            IQueryable<T> source,
            int pageIndex = 1,
            int pageSize = 10,
            CancellationToken ct = default)
        {
            var total = await source.CountAsync(ct);
            var items = await source.Skip((pageIndex - 1) * pageSize)
                                    .Take(pageSize)
                                    .ToListAsync(ct);
            // 使用显式传入 totalCount 的构造函数
            return new PaginatedResult<T>(items, total, pageIndex, pageSize);
        }

        /// <summary>
        /// 创建空的分页结果
        /// </summary>
        public static PaginatedResult<T> Empty => new(Array.Empty<T>(), 0, 1, 10);
    }

}
