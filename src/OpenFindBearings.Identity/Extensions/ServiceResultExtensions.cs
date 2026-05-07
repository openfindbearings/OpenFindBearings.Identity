using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Extensions
{
    public static class ServiceResultExtensions
    {
        /// <summary>
        /// 将 ServiceError[] 转换为 Dictionary&lt;string, string[]&gt;
        /// Key = 错误码 (Code), Value = 对应的错误描述数组
        /// </summary>
        public static Dictionary<string, string[]> ToErrorDictionary(this ServiceError[] errors)
        {
            if (errors == null || errors.Length == 0)
                return new Dictionary<string, string[]>();

            return errors
                .GroupBy(e => e.Code)
                .ToDictionary(
                    g => g.Key,
                    g => g.Select(e => e.Description).ToArray()
                );
        }

        /// <summary>
        /// 从 ServiceResult 中提取错误字典
        /// </summary>
        public static Dictionary<string, string[]> GetErrorDictionary(this ServiceResult result)
        {
            return result.Errors.ToErrorDictionary();
        }

        /// <summary>
        /// 从 ServiceResult&lt;T&gt; 中提取错误字典
        /// </summary>
        public static Dictionary<string, string[]> GetErrorDictionary<T>(this ServiceResult<T> result)
        {
            return result.Errors.ToErrorDictionary();
        }
    }
}
