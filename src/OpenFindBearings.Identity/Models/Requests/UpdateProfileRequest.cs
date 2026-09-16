using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 更新个人资料请求
    /// </summary>
    public class UpdateProfileRequest
    {
        /// <summary>
        /// 全名
        /// </summary>
        [StringLength(100, ErrorMessage = "姓名不能超过100个字符")]
        public string? Name { get; set; }

        /// <summary>
        /// 名
        /// </summary>
        [StringLength(50, ErrorMessage = "名不能超过50个字符")]
        public string? GivenName { get; set; }

        /// <summary>
        /// 姓
        /// </summary>
        [StringLength(50, ErrorMessage = "姓不能超过50个字符")]
        public string? FamilyName { get; set; }

        /// <summary>
        /// 昵称
        /// </summary>
        [StringLength(50, ErrorMessage = "昵称不能超过50个字符")]
        public string? Nickname { get; set; }

        /// <summary>
        /// 头像 URL
        /// 改动说明：[Url] 改相对/绝对双允许正则——头像现按"相对媒体键入库、前端拼媒体源"的主流做法
        /// （如 /uploads/avatars/xxx.jpg），绝对 http(s) 仍兼容；避免把 host 焊进库导致换域名/切对象存储全炸
        /// </summary>
        [RegularExpression(@"^(https?://|/).+", ErrorMessage = "头像地址格式不正确")]
        [StringLength(500, ErrorMessage = "URL不能超过500个字符")]
        public string? PictureUrl { get; set; }

        /// <summary>
        /// 个人网站 URL
        /// </summary>
        [Url(ErrorMessage = "网站URL格式不正确")]
        [StringLength(500, ErrorMessage = "URL不能超过500个字符")]
        public string? WebsiteUrl { get; set; }

        /// <summary>
        /// 性别
        /// </summary>
        [RegularExpression("^(male|female|other)$", ErrorMessage = "性别必须是 male、female 或 other")]
        public string? Gender { get; set; }

        /// <summary>
        /// 出生日期
        /// </summary>
        [DataType(DataType.Date)]
        public DateOnly? Birthdate { get; set; }

        /// <summary>
        /// 地区/语言
        /// </summary>
        [StringLength(10, ErrorMessage = "地区代码不能超过10个字符")]
        public string? Locale { get; set; }

        /// <summary>
        /// 时区
        /// </summary>
        [StringLength(50, ErrorMessage = "时区不能超过50个字符")]
        public string? ZoneInfo { get; set; }

        /// <summary>
        /// 地址
        /// </summary>
        public AddressRequest? Address { get; set; }
    }

    /// <summary>
    /// 地址请求
    /// </summary>
    public class AddressRequest
    {
        [StringLength(100, ErrorMessage = "国家不能超过100个字符")]
        public string? Country { get; set; }

        [StringLength(100, ErrorMessage = "省/州不能超过100个字符")]
        public string? Region { get; set; }

        [StringLength(100, ErrorMessage = "城市不能超过100个字符")]
        public string? Locality { get; set; }

        [StringLength(200, ErrorMessage = "街道地址不能超过200个字符")]
        public string? StreetAddress { get; set; }

        [StringLength(20, ErrorMessage = "邮政编码不能超过20个字符")]
        public string? PostalCode { get; set; }
    }
}
