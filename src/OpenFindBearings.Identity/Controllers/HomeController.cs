using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenFindBearings.Identity.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly Data.ApplicationDbContext _db;

        public HomeController(Data.ApplicationDbContext db)
        {
            _db = db;
        }

        public async Task<IActionResult> Index()
        {
            ViewBag.UserCount = await _db.Users.CountAsync();
            ViewBag.TenantCount = await _db.Tenants.CountAsync();
            ViewBag.ClientCount = (await _db.Set<OpenIddictEntityFrameworkCoreApplication>().ToListAsync()).Count;
            ViewBag.ScopeCount = (await _db.Set<OpenIddictEntityFrameworkCoreScope>().ToListAsync()).Count;
            return View();
        }
    }
}
