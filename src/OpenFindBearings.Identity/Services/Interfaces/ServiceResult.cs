namespace OpenFindBearings.Identity.Services.Interfaces
{
    /// <summary>
    /// 服务调用结果（无返回值）
    /// </summary>
    public class ServiceResult
    {
        public bool IsSuccess { get; }
        public string[] Errors { get; }

        protected ServiceResult(bool isSuccess, string[] errors)
        {
            IsSuccess = isSuccess;
            Errors = errors ?? Array.Empty<string>();
        }

        public static ServiceResult Success() => new(true, Array.Empty<string>());
        public static ServiceResult Failure(string error) => new(false, new[] { error });
        public static ServiceResult Failure(string[] errors) => new(false, errors);
    }

    /// <summary>
    /// 服务调用结果（带返回值）
    /// </summary>
    public class ServiceResult<T> : ServiceResult
    {
        public T? Data { get; }

        private ServiceResult(bool isSuccess, string[] errors, T? data) : base(isSuccess, errors)
        {
            Data = data;
        }

        public static ServiceResult<T> Success(T data) => new(true, Array.Empty<string>(), data);
        public new static ServiceResult<T> Failure(string error) => new(false, new[] { error }, default);
        public new static ServiceResult<T> Failure(string[] errors) => new(false, errors, default);
    }
}
