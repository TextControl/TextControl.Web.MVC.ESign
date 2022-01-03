using ActionFilters.ActionFilters;
using esign.Helpers;
using esign.Models;
using LiteDB;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
namespace esign.Controllers {

	public class NewController : Controller {

		private readonly ILogger<NewController> _logger;
		private readonly UserManager<LiteDB.Identity.Models.LiteDbUser> _userManager;
		private readonly SignInManager<LiteDB.Identity.Models.LiteDbUser> _signInManager;

		public NewController(ILogger<NewController> logger, UserManager<LiteDB.Identity.Models.LiteDbUser> userManager, SignInManager<LiteDB.Identity.Models.LiteDbUser> signInManager) {
			_logger = logger;
			_userManager = userManager;
			_signInManager = signInManager;
		}

		public IActionResult Index() {

			if (User.Identity.IsAuthenticated == false) {
				var returnUrl = Url.Action("index", "new");
				var dummyEmail = Guid.NewGuid().ToString();

				var user = new LiteDB.Identity.Models.LiteDbUser { UserName = dummyEmail, Email = dummyEmail };
				var result = _userManager.CreateAsync(user, "Esign#2021").Result;

				var signedIn = _signInManager.PasswordSignInAsync(dummyEmail, "Esign#2021", true, lockoutOnFailure: false).Result;
				return LocalRedirect(returnUrl);
			}

			return View();
		}

		[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
		public IActionResult Error() {
			return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
		}
	}
}
