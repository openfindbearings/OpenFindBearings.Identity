namespace OpenFindBearings.Identity.Services.Interfaces
{
    /// <summary>
    /// 服务调用结果（无返回值）
    /// </summary>
    public class ServiceResult
    {
        public bool IsSuccess { get; }
        public ServiceError[] Errors { get; }

        protected ServiceResult(bool isSuccess, ServiceError[] errors)
        {
            IsSuccess = isSuccess;
            Errors = errors ?? [];
        }

        public static ServiceResult Success() => new(true, []);
        public static ServiceResult Failure(ServiceError error) => new(false, [error]);
        public static ServiceResult Failure(ServiceError[] errors) => new(false, errors);
    }

    public class ServiceError
    {
        public string Code { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }

    /// <summary>
    /// 服务调用结果（带返回值）
    /// </summary>
    public class ServiceResult<T> : ServiceResult
    {
        public T? Data { get; }

        private ServiceResult(bool isSuccess, ServiceError[] errors, T? data) : base(isSuccess, errors)
        {
            Data = data;
        }

        public static ServiceResult<T> Success(T data) => new(true, [], data);
        public new static ServiceResult<T> Failure(ServiceError error) => new(false, [error], default);
        public new static ServiceResult<T> Failure(ServiceError[] errors) => new(false, errors, default);
    }
}
