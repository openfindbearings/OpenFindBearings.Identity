using System.ComponentModel.DataAnnotations;

namespace OpenFindBearings.Identity.Models.DTOs.Tenant
{
    public class CreateTenantDto
    {
        [Required(ErrorMessage = "租户名称不能为空")]
        [MaxLength(200)]
        public string Name { get; set; } = string.Empty;

        [MaxLength(500)]
        public string? Description { get; set; }
    }
}
