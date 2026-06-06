namespace OpenFindBearings.Identity.Models.Responses
{
    /// <summary>
    /// 统一API响应格式
    /// </summary>
    /// <typeparam name="T">数据类型</typeparam>
    public class ApiResponse<T>
    {
        /// <summary>
        /// 是否成功
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// 状态码 (200, 400, 401, 404, 500等)
        /// </summary>
        public int Code { get; set; }

        /// <summary>
        /// 消息（可用于多语言）
        /// </summary>
        public string? Message { get; set; }

        /// <summary>
        /// 数据
        /// </summary>
        public T? Data { get; set; }

        /// <summary>
        /// 错误详情（用于验证错误）
        /// </summary>
        public Dictionary<string, string[]>? Errors { get; set; }

        /// <summary>
        /// 时间戳
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// 请求追踪ID
        /// </summary>
        public string? TraceId { get; set; }

        public ApiResponse() { }

        public ApiResponse(T data, string? message = null)
        {
            Success = true;
            Code = 200;
            Data = data;
            Message = message;
        }

        /// <summary>
        /// 创建成功响应（200）
        /// </summary>
        public static ApiResponse<T> SuccessResult(T data, string? message = null)
        {
            return new ApiResponse<T>
            {
                Success = true,
                Code = 200,
                Data = data,
                Message = message
            };
        }

        /// <summary>
        /// 创建错误响应
        /// </summary>
        public static ApiResponse<T> ErrorResult(string message, int code = 400, Dictionary<string, string[]>? errors = null)
        {
            return new ApiResponse<T>
            {
                Success = false,
                Code = code,
                Message = message,
                Errors = errors
            };
        }

        /// <summary>
        /// 创建已接受响应（202）
        /// </summary>
        public static ApiResponse<T> AcceptedResult(T data, string? message = null, HttpContext? httpContext = null)
        {
            return new ApiResponse<T>
            {
                Success = true,
                Code = 202,
                Data = data,
                Message = message,
                TraceId = httpContext?.TraceIdentifier
            };
        }
    }
}
