using System.Text.Json;

namespace OpenFindBearings.Identity.Models.Entities
{
    /// <summary>
    /// 系统配置实体 - 存储键值对配置
    /// 采用充血模型设计，通过工厂方法创建，属性不可变
    /// </summary>
    public class SystemConfig
    {
        /// <summary>
        /// 无参构造函数 - EF Core 需要（private 确保外部不能直接 new）
        /// </summary>
        private SystemConfig() { }

        /// <summary>
        /// 私有构造函数 - 由工厂方法调用
        /// </summary>
        private SystemConfig(string key, string value, string? description)
        {
            Id = Guid.NewGuid();
            Key = key;
            Value = value;
            Description = description;
            CreatedAt = DateTimeOffset.UtcNow;
            UpdatedAt = null;
        }

        // ========== 属性（全部 private set） ==========

        /// <summary>
        /// 主键
        /// </summary>
        public Guid Id { get; private set; }

        /// <summary>
        /// 配置键（唯一）
        /// </summary>
        public string Key { get; private set; } = string.Empty;

        /// <summary>
        /// 配置值（JSON 格式）
        /// </summary>
        public string Value { get; private set; } = string.Empty;

        /// <summary>
        /// 描述
        /// </summary>
        public string? Description { get; private set; }

        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTimeOffset CreatedAt { get; private set; }

        /// <summary>
        /// 更新时间
        /// </summary>
        public DateTimeOffset? UpdatedAt { get; private set; }

        // ========== 工厂方法 ==========

        /// <summary>
        /// 创建系统配置（字符串值）
        /// </summary>
        /// <param name="key">配置键（唯一标识）</param>
        /// <param name="value">配置值</param>
        /// <param name="description">描述（可选）</param>
        /// <returns>系统配置实体</returns>
        public static SystemConfig Create(string key, string value, string? description = null)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("配置键不能为空", nameof(key));

            if (value == null)
                throw new ArgumentException("配置值不能为 null", nameof(value));

            return new SystemConfig(key, value, description);
        }

        /// <summary>
        /// 创建系统配置（对象值，自动序列化为 JSON）
        /// </summary>
        /// <typeparam name="T">值类型</typeparam>
        /// <param name="key">配置键（唯一标识）</param>
        /// <param name="value">配置值对象</param>
        /// <param name="description">描述（可选）</param>
        /// <returns>系统配置实体</returns>
        public static SystemConfig Create<T>(string key, T value, string? description = null)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("配置键不能为空", nameof(key));

            if (value == null)
                throw new ArgumentException("配置值不能为 null", nameof(value));

            var jsonValue = JsonSerializer.Serialize(value);
            return new SystemConfig(key, jsonValue, description);
        }

        /// <summary>
        /// 从已有数据重建配置（用于数据库查询后的反序列化场景）
        /// </summary>
        /// <param name="id">主键</param>
        /// <param name="key">配置键</param>
        /// <param name="value">配置值</param>
        /// <param name="description">描述</param>
        /// <param name="createdAt">创建时间</param>
        /// <param name="updatedAt">更新时间</param>
        /// <returns>系统配置实体</returns>
        public static SystemConfig Rehydrate(
            Guid id,
            string key,
            string value,
            string? description,
            DateTimeOffset createdAt,
            DateTimeOffset? updatedAt)
        {
            var config = new SystemConfig(key, value, description);

            // 通过反射设置 Id 和 CreatedAt（仅用于反序列化场景）
            SetIdViaReflection(config, id);
            SetCreatedAtViaReflection(config, createdAt);
            SetUpdatedAtViaReflection(config, updatedAt);

            return config;
        }

        // ========== 业务方法 ==========

        /// <summary>
        /// 更新配置值（字符串）
        /// </summary>
        /// <param name="newValue">新值</param>
        /// <param name="description">新描述（可选，不传则保持原值）</param>
        public void Update(string newValue, string? description = null)
        {
            if (newValue == null)
                throw new ArgumentException("配置值不能为 null", nameof(newValue));

            Value = newValue;

            if (description != null)
                Description = description;

            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 更新配置值（对象，自动序列化为 JSON）
        /// </summary>
        /// <typeparam name="T">值类型</typeparam>
        /// <param name="newValue">新值对象</param>
        /// <param name="description">新描述（可选，不传则保持原值）</param>
        public void Update<T>(T newValue, string? description = null)
        {
            if (newValue == null)
                throw new ArgumentException("配置值不能为 null", nameof(newValue));

            Value = JsonSerializer.Serialize(newValue);

            if (description != null)
                Description = description;

            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 更新描述
        /// </summary>
        /// <param name="description">新描述</param>
        public void UpdateDescription(string? description)
        {
            Description = description;
            UpdatedAt = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// 获取配置值（字符串）
        /// </summary>
        public string GetValue() => Value;

        /// <summary>
        /// 获取配置值（反序列化为对象）
        /// </summary>
        /// <typeparam name="T">目标类型</typeparam>
        /// <returns>反序列化后的对象</returns>
        public T? GetValue<T>()
        {
            if (string.IsNullOrEmpty(Value))
                return default;

            return JsonSerializer.Deserialize<T>(Value);
        }

        /// <summary>
        /// 尝试获取配置值（反序列化为对象，带默认值）
        /// </summary>
        /// <typeparam name="T">目标类型</typeparam>
        /// <param name="defaultValue">默认值</param>
        /// <returns>配置值或默认值</returns>
        public T GetValueOrDefault<T>(T defaultValue)
        {
            if (string.IsNullOrEmpty(Value))
                return defaultValue;

            try
            {
                var result = JsonSerializer.Deserialize<T>(Value);
                return result != null ? result : defaultValue;
            }
            catch (JsonException)
            {
                return defaultValue;
            }
        }

        /// <summary>
        /// 检查是否为指定键
        /// </summary>
        public bool IsKey(string key) => string.Equals(Key, key, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// 检查配置值是否为有效的 JSON
        /// </summary>
        public bool IsValidJson()
        {
            if (string.IsNullOrWhiteSpace(Value))
                return false;

            try
            {
                JsonDocument.Parse(Value);
                return true;
            }
            catch (JsonException)
            {
                return false;
            }
        }

        // ========== 反射辅助方法（仅用于 Rehydrate） ==========

        private static void SetIdViaReflection(SystemConfig config, Guid id)
        {
            var property = typeof(SystemConfig).GetProperty("Id");
            if (property != null && property.CanWrite)
            {
                property.SetValue(config, id);
            }
        }

        private static void SetCreatedAtViaReflection(SystemConfig config, DateTimeOffset createdAt)
        {
            var field = typeof(SystemConfig).GetField("<CreatedAt>k__BackingField",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            if (field != null)
            {
                field.SetValue(config, createdAt);
            }
        }

        private static void SetUpdatedAtViaReflection(SystemConfig config, DateTimeOffset? updatedAt)
        {
            var field = typeof(SystemConfig).GetField("<UpdatedAt>k__BackingField",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            if (field != null)
            {
                field.SetValue(config, updatedAt);
            }
        }

        // ========== 辅助方法 ==========

        /// <summary>
        /// 转换为字符串（用于调试）
        /// </summary>
        public override string ToString()
        {
            return $"{Key} = {Value}";
        }
    }
}
