namespace OpenFindBearings.Identity.Models.Requests
{
    /// <summary>
    /// 管理员更新用户请求
    /// </summary>
    public class AdminUpdateUserRequest : UpdateProfileRequest
    {
        public List<string>? Roles { get; set; }
    }
}
