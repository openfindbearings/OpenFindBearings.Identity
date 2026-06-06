using OpenFindBearings.Identity.Models.ValueObjects;

namespace OpenFindBearings.Identity.Models.DTOs.User
{
    /// <summary>
    /// 更新用户请求 DTO
    /// </summary>
    public class UpdateUserDto
    {
        /// <summary>全名</summary>
        public string? Name { get; set; }

        /// <summary>名</summary>
        public string? GivenName { get; set; }

        /// <summary>姓</summary>
        public string? FamilyName { get; set; }

        /// <summary>昵称</summary>
        public string? Nickname { get; set; }

        /// <summary>头像 URL</summary>
        public string? PictureUrl { get; set; }

        /// <summary>个人网站 URL</summary>
        public string? WebsiteUrl { get; set; }

        /// <summary>性别</summary>
        public string? Gender { get; set; }

        /// <summary>出生日期</summary>
        public DateOnly? Birthdate { get; set; }

        /// <summary>语言区域</summary>
        public string? Locale { get; set; }

        /// <summary>时区</summary>
        public string? ZoneInfo { get; set; }

        /// <summary>地址</summary>
        public Address? Address { get; set; }
    }
}
