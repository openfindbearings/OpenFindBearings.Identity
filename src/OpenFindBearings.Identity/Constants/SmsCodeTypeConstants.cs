namespace OpenFindBearings.Identity.Constants
{
    // SmsCode 实体中有 Type 字段，需要这些常量
    public static class SmsCodeTypeConstants
    {
        public const string Login = "login";
        public const string Register = "register";
        public const string Bind = "bind";
        public const string ResetPassword = "reset_password";
    }
}
