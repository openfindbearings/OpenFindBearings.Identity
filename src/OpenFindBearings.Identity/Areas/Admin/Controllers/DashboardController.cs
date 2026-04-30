using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenFindBearings.Identity.Services.Interfaces;

namespace OpenFindBearings.Identity.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "SuperAdmin,Admin")]
    public class DashboardController : Controller
    {
        private readonly IUserService _userService;
        private readonly IAuditLogService _auditLogService;

        public DashboardController(
            IUserService userService,
            IAuditLogService auditLogService)
        {
            _userService = userService;
            _auditLogService = auditLogService;
        }

        public async Task<IActionResult> Index()
        {
            var totalUsers = await _userService.GetCountAsync();
            var todayLogs = await _auditLogService.GetTodayCountAsync();

            ViewBag.TotalUsers = totalUsers;
            ViewBag.TodayLogs = todayLogs;

            return View();
        }
    }
}
