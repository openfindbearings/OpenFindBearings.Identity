namespace OpenFindBearings.Identity.Models.DTOs
{
    /// <summary>
    /// 更新用户请求
    /// </summary>
    public class UpdateUserRequest
    {
        /// <summary>
        /// 全名
        /// </summary>
        public string? Name { get; set; }

        /// <summary>
        /// 名
        /// </summary>
        public string? GivenName { get; set; }

        /// <summary>
        /// 姓
        /// </summary>
        public string? FamilyName { get; set; }

        /// <summary>
        /// 昵称
        /// </summary>
        public string? Nickname { get; set; }

        /// <summary>
        /// 头像 URL
        /// </summary>
        public string? PictureUrl { get; set; }

        /// <summary>
        /// 个人网站 URL
        /// </summary>
        public string? WebsiteUrl { get; set; }
    }
}
