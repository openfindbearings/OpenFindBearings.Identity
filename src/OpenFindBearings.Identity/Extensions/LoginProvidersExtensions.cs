using OpenFindBearings.Identity.Models.Enums;

namespace OpenFindBearings.Identity.Extensions
{
    public static class LoginProvidersExtensions
    {
        public static string ToLowerString(this LoginProviders loginType)
        {
            return loginType.ToString().ToLowerInvariant();
        }
    }
}
