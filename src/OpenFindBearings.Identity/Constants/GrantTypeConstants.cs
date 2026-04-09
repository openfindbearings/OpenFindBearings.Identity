using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenFindBearings.Identity.Constants
{
    public static class GrantTypeConstants
    {
        public const string Sms = "sms";
        public const string WeChat = "wechat";
        public const string QQ = "qq";
        public const string Biometric = "biometric";

        public const string AuthorizationCode = GrantTypes.AuthorizationCode;
        public const string ClientCredentials = GrantTypes.ClientCredentials;
        public const string Password = GrantTypes.Password;
        public const string RefreshToken = GrantTypes.RefreshToken;
    }
}
