namespace OpenFindBearings.Identity.Helpers
{
    /// <summary>
    /// 密码哈希服务实现（使用BCrypt）
    /// </summary>
    public static class PasswordHasher
    {
        public static string CreateHash(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password); 
        }

        public static bool Verify(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
    }
}
