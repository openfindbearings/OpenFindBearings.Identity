using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Models.Responses;

namespace OpenFindBearings.Identity.Helpers
{
    /// <summary>
    /// API 响应辅助类（Controller 版本）
    /// </summary>
    public static class ApiResponseHelper
    {
        /// <summary>
        /// 返回 200 OK 成功响应
        /// </summary>
        public static ActionResult<ApiResponse<T>> Success<T>(ControllerBase controller, T data, string? message = null)
        {
            return controller.Ok(ApiResponse<T>.SuccessResult(data, message));
        }

        /// <summary>
        /// 返回 201 Created 响应（配合 GET 端点）
        /// </summary>
        public static ActionResult<ApiResponse<T>> Created<T>(
            ControllerBase controller,
            string actionName,
            object routeValues,
            T data,
            string? message = null)
        {
            var response = ApiResponse<T>.SuccessResult(data, message);
            return controller.CreatedAtAction(actionName, routeValues, response);
        }

        /// <summary>
        /// 返回 201 Created 响应（无 GET 端点时使用）
        /// </summary>
        public static ActionResult<ApiResponse<T>> Created<T>(
            ControllerBase controller,
            string uri,
            T data,
            string? message = null)
        {
            var response = ApiResponse<T>.SuccessResult(data, message);
            return controller.Created(uri, response);
        }

        /// <summary>
        /// 返回 400 Bad Request 错误
        /// </summary>
        public static ActionResult<ApiResponse<T>> BadRequest<T>(
            ControllerBase controller,
            string message,
            Dictionary<string, string[]>? errors = null)
        {
            return controller.BadRequest(ApiResponse<T>.ErrorResult(message, 400, errors));
        }

        /// <summary>
        /// 返回 401 Unauthorized
        /// </summary>
        public static ActionResult<ApiResponse<T>> Unauthorized<T>(
            ControllerBase controller,
            string message = "Unauthorized")
        {
            return controller.Unauthorized(ApiResponse<T>.ErrorResult(message, 401));
        }

        /// <summary>
        /// 返回 403 Forbidden
        /// </summary>
        public static ActionResult<ApiResponse<T>> Forbidden<T>(
            ControllerBase controller,
            string message = "Forbidden")
        {
            return controller.StatusCode(403, ApiResponse<T>.ErrorResult(message, 403));
        }

        /// <summary>
        /// 返回 404 Not Found
        /// </summary>
        public static ActionResult<ApiResponse<T>> NotFound<T>(
            ControllerBase controller,
            string message = "Resource not found")
        {
            return controller.NotFound(ApiResponse<T>.ErrorResult(message, 404));
        }

        /// <summary>
        /// 返回 409 Conflict
        /// </summary>
        public static ActionResult<ApiResponse<T>> Conflict<T>(
            ControllerBase controller,
            string message = "Resource already exists")
        {
            return controller.Conflict(ApiResponse<T>.ErrorResult(message, 409));
        }

        /// <summary>
        /// 返回 422 Unprocessable Entity
        /// </summary>
        public static ActionResult<ApiResponse<T>> UnprocessableEntity<T>(
            ControllerBase controller,
            string message,
            Dictionary<string, string[]>? errors = null)
        {
            return controller.UnprocessableEntity(ApiResponse<T>.ErrorResult(message, 422, errors));
        }

        /// <summary>
        /// 返回 500 Internal Server Error
        /// </summary>
        public static ActionResult<ApiResponse<T>> InternalError<T>(
            ControllerBase controller,
            string message = "Internal server error")
        {
            return controller.StatusCode(500, ApiResponse<T>.ErrorResult(message, 500));
        }
    }
}
