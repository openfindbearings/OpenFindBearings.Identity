using PhoneNumbers;
using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Helpers
{
    /// <summary>
    /// 手机号验证辅助类（基于 libphonenumber）
    /// </summary>
    public static class PhoneNumberHelper
    {
        private static readonly PhoneNumberUtil _phoneNumberUtil;

        static PhoneNumberHelper()
        {
            _phoneNumberUtil = PhoneNumberUtil.GetInstance();
        }

        /// <summary>
        /// 验证手机号是否有效
        /// </summary>
        /// <param name="phoneNumber">手机号</param>
        /// <param name="defaultRegion">默认地区代码（如 "CN"、"US"）</param>
        /// <param name="requireMobile">是否要求必须是手机号（而非固定电话）</param>
        /// <returns></returns>
        public static bool IsValid(string phoneNumber, string defaultRegion = "CN", bool requireMobile = true)
        {
            if (string.IsNullOrWhiteSpace(phoneNumber))
                return false;

            try
            {
                var parsed = _phoneNumberUtil.Parse(phoneNumber, defaultRegion);

                // 基本有效性验证
                if (!_phoneNumberUtil.IsValidNumber(parsed))
                    return false;

                // 可选：要求必须是手机号
                if (requireMobile)
                {
                    var numberType = _phoneNumberUtil.GetNumberType(parsed);
                    return numberType == PhoneNumberType.MOBILE ||
                           numberType == PhoneNumberType.FIXED_LINE_OR_MOBILE;
                }

                return true;
            }
            catch (NumberParseException)
            {
                return false;
            }
        }

        /// <summary>
        /// 格式化手机号为国际标准格式
        /// </summary>
        public static string FormatInternational(string phoneNumber, string defaultRegion = "CN")
        {
            try
            {
                var parsed = _phoneNumberUtil.Parse(phoneNumber, defaultRegion);
                return _phoneNumberUtil.Format(parsed, PhoneNumberFormat.INTERNATIONAL);
            }
            catch
            {
                return phoneNumber;
            }
        }

        /// <summary>
        /// 格式化手机号为 E.164 格式（纯数字，带+号）
        /// </summary>
        public static string FormatE164(string phoneNumber, string defaultRegion = "CN")
        {
            try
            {
                var parsed = _phoneNumberUtil.Parse(phoneNumber, defaultRegion);
                return _phoneNumberUtil.Format(parsed, PhoneNumberFormat.E164);
            }
            catch
            {
                return phoneNumber;
            }
        }

        /// <summary>
        /// 获取手机号的地区信息
        /// </summary>
        public static string? GetRegionCode(string phoneNumber, string defaultRegion = "CN")
        {
            try
            {
                var parsed = _phoneNumberUtil.Parse(phoneNumber, defaultRegion);
                return _phoneNumberUtil.GetRegionCodeForNumber(parsed);
            }
            catch
            {
                return null;
            }
        }
    }

    /// <summary>
    /// 国际手机号验证特性（基于 libphonenumber）
    /// </summary>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter, AllowMultiple = false)]
    public class PhoneNumberAttribute : ValidationAttribute
    {
        /// <summary>
        /// 默认地区代码（如 "CN" 表示中国，"US" 表示美国）
        /// </summary>
        public string DefaultRegion { get; set; } = "CN";

        /// <summary>
        /// 是否要求必须是手机号（而非固定电话）
        /// </summary>
        public bool RequireMobile { get; set; } = true;

        public PhoneNumberAttribute()
        {
            ErrorMessage = "手机号格式不正确";
        }

        protected override ValidationResult IsValid(object? value, ValidationContext validationContext)
        {
            // 如果允许为空，且值为空，则跳过验证
            if (value == null || string.IsNullOrWhiteSpace(value.ToString()))
            {
                return ValidationResult.Success!;
            }

            string phoneNumber = value.ToString()!.Trim();

            // 调用 PhoneNumberHelper 进行验证
            bool isValid = PhoneNumberHelper.IsValid(phoneNumber, DefaultRegion, RequireMobile);

            if (!isValid)
            {
                // 可以自定义更详细的错误信息
                string errorMessage = string.IsNullOrEmpty(ErrorMessage)
                    ? $"手机号格式不正确{(RequireMobile ? "（必须是手机号）" : "")}"
                    : ErrorMessage;

                return new ValidationResult(errorMessage, new[] { validationContext.MemberName! });
            }

            return ValidationResult.Success!;
        }
    }
}
