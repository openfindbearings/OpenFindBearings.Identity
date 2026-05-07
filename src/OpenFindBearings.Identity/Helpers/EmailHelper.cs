using System.Text.RegularExpressions;

namespace OpenFindBearings.Identity.Helpers
{
    /// <summary>
    /// 基于正则表达式的邮箱验证辅助类（性能更优）
    /// </summary>
    public static class EmailHelper
    {
        // RFC 2822 标准简化版正则（覆盖99%的常见邮箱）
        private static readonly Regex EmailRegex = new(
            @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase,
            TimeSpan.FromSeconds(1)
        );

        // 更严格的正则（符合大多数实际应用要求）
        private static readonly Regex StrictEmailRegex = new(
            @"^(?!\.)[a-zA-Z0-9._%+-]{1,64}(?<!\.)@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase,
            TimeSpan.FromSeconds(1)
        );

        /// <summary>
        /// 验证邮箱格式（快速正则版本）
        /// </summary>
        public static bool IsValid(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            // 总长度限制
            if (email.Length > 254)
                return false;

            return EmailRegex.IsMatch(email);
        }

        /// <summary>
        /// 严格验证邮箱格式
        /// </summary>
        public static bool IsValidStrict(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            if (email.Length > 254)
                return false;

            // 检查@符号位置
            int atIndex = email.IndexOf('@');
            if (atIndex <= 0 || atIndex >= email.Length - 3)
                return false;

            // 检查本地部分长度
            if (atIndex > 64)
                return false;

            return StrictEmailRegex.IsMatch(email);
        }

        /// <summary>
        /// 批量验证邮箱
        /// </summary>
        public static List<string> FilterValidEmails(IEnumerable<string> emails)
        {
            return emails?.Where(IsValid).ToList() ?? new List<string>();
        }
    }
}
