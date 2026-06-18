namespace OpenFindBearings.Identity.Models.DTOs
{
    public class TenantInfo
    {
        public Guid? TenantId { get; set; }
        public string? Realm { get; set; }
        public string? TenantName { get; set; }
        public string? TenantDescription { get; set; }

        public bool IsResolved => TenantId.HasValue || !string.IsNullOrEmpty(Realm);
    }
}
