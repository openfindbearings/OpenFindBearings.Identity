using OpenFindBearings.Identity.Helpers;
using OpenFindBearings.Identity.Models.DTOs.AuditLog;
using OpenFindBearings.Identity.Models.DTOs.SystemConfig;
using OpenFindBearings.Identity.Models.DTOs.User;
using OpenFindBearings.Identity.Models.Entities;
using OpenFindBearings.Identity.Models.Requests;
using OpenFindBearings.Identity.Models.Responses;
using OpenFindBearings.Identity.Models.ValueObjects;

namespace OpenFindBearings.Identity.Extensions
{
    public static class MappingExtensions
    {
        #region Request → DTO 
        public static CreateUserDto ToDto(this SignUpRequest request)
        {
            return new CreateUserDto
            {
                UserName = request.Account,
                Email = EmailHelper.IsValid(request.Account) ? request.Account : null,
                PhoneNumber = PhoneNumberHelper.IsValid(request.Account) ? request.Account : null,
                Password = request.Password,
                Name = null,
                GivenName = null,
                FamilyName = null,
                Nickname = null
            };
        }

        public static UpdateUserDto ToDto(this UpdateProfileRequest request)
        {
            var dto = new UpdateUserDto
            {
                Name = request.Name,
                GivenName = request.GivenName,
                FamilyName = request.FamilyName,
                Nickname = request.Nickname,
                PictureUrl = request.PictureUrl,
                WebsiteUrl = request.WebsiteUrl,
                Gender = request.Gender,
                Birthdate = request.Birthdate,
                Locale = request.Locale,
                ZoneInfo = request.ZoneInfo
            };

            if (request.Address != null)
            {
                dto.Address = new Models.ValueObjects.Address
                {
                    Country = request.Address.Country,
                    Region = request.Address.Region,
                    Locality = request.Address.Locality,
                    StreetAddress = request.Address.StreetAddress,
                    PostalCode = request.Address.PostalCode
                };
            }

            return dto;
        }

        #endregion

        #region DTO → Response
        public static UserResponse ToResponse(this UserDto dto)
        {
            return new UserResponse
            {
                Id = dto.Id,
                UserName = dto.UserName,
                Email = dto.Email,
                EmailVerified = dto.EmailVerified,
                PhoneNumber = dto.PhoneNumber,
                PhoneNumberVerified = dto.PhoneNumberVerified,
                Name = dto.Name,
                GivenName = dto.GivenName,
                FamilyName = dto.FamilyName,
                Nickname = dto.Nickname,
                PictureUrl = dto.PictureUrl,
                WebsiteUrl = dto.WebsiteUrl,
                Gender = dto.Gender,
                Birthdate = dto.Birthdate,
                Locale = dto.Locale,
                ZoneInfo = dto.ZoneInfo,
                Address = dto.Address.ToResponse(),
                IsEnabled = dto.IsEnabled,
                IsActive = dto.IsActive,
                CreatedAt = dto.CreatedAt,
                UpdatedAt = dto.UpdatedAt,
                LastLoginAt = dto.LastLoginAt,
                TenantId = dto.TenantId,
                Roles = dto.Roles
            };
        }

        #endregion

        #region DTO → Entity
        //public static OidcUser ToEntity(CreateUserDto dto, IPasswordHasher hasher)
        //{
        //    return new OidcUser
        //    {
        //        Id = Guid.NewGuid(),
        //        UserName = dto.UserName,
        //        Email = dto.Email,
        //        PhoneNumber = dto.PhoneNumber,
        //        PasswordHash = hasher.HashPassword(dto.Password),
        //        CreatedAt = DateTimeOffset.UtcNow,
        //        IsActive = true,
        //        IsEnabled = true
        //    };
        //}
        #endregion

        #region Entity → DTO
        public static UserDto ToDto(this OidcUser user)
        {
            return new UserDto
            {
                Id = user.Id,
                Sub = user.Sub,
                UserName = user.UserName,
                Email = user.Email,
                EmailVerified = user.EmailVerified,
                PhoneNumber = user.PhoneNumber,
                PhoneNumberVerified = user.PhoneNumberVerified,
                Name = user.Name,
                GivenName = user.GivenName,
                FamilyName = user.FamilyName,
                Nickname = user.Nickname,
                PictureUrl = user.PictureUrl,
                WebsiteUrl = user.WebsiteUrl,
                Gender = user.Gender,
                Birthdate = user.Birthdate,
                Locale = user.Locale,
                ZoneInfo = user.ZoneInfo,
                Address = user.Address,
                TenantId = user.TenantId,
                IsEnabled = user.IsEnabled,
                IsActive = user.IsActive,
                LastLoginAt = user.LastLoginAt,
                LastLoginIp = user.LastLoginIp,
                LastLoginDevice = user.LastLoginDevice,
                CreatedAt = user.CreatedAt,
                UpdatedAt = user.UpdatedAt
            };
        }

        public static SystemConfigDto ToDto(this SystemConfig config)
        {
            return new SystemConfigDto
            {
                Key = config.Key,
                Value = config.GetValue(),
                Description = config.Description,
                UpdatedAt = config.UpdatedAt ?? config.CreatedAt
            };
        }

        /// <summary>
        /// 实体转DTO
        /// </summary>
        public static AuditLogDto ToDto(this AuditLog log)
        {
            return new AuditLogDto
            {
                Id = log.Id,
                UserId = log.UserId,
                Username = log.Username,
                Action = log.Action,
                ResourceType = log.ResourceType,
                ResourceId = log.ResourceId,
                Details = log.Details,
                Status = log.Status,
                FailureReason = log.FailureReason,
                ClientId = log.ClientId,
                IpAddress = log.IpAddress,
                UserAgent = log.UserAgent,
                CreatedAt = log.CreatedAt
            };
        }
        #endregion

        #region Entity → Response

        /// <summary>
        /// 将值对象 Address 转换为 AddressResponse
        /// </summary>
        public static AddressResponse? ToResponse(this Address? address)
        {
            if (address == null) return null;

            return new AddressResponse
            {
                Formatted = address.Formatted,
                StreetAddress = address.StreetAddress,
                Locality = address.Locality,
                Region = address.Region,
                PostalCode = address.PostalCode,
                Country = address.Country
            };
        }

        #endregion
    }
}
