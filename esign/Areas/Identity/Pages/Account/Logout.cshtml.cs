using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace esign.Identity.Pages.Account {

	[AllowAnonymous]
	public class LogoutModel : PageModel {
		private readonly SignInManager<LiteDB.Identity.Models.LiteDbUser> _signInManager;
		private readonly ILogger<LogoutModel> _logger;

		public LogoutModel(SignInManager<LiteDB.Identity.Models.LiteDbUser> signInManager, ILogger<LogoutModel> logger) {
			_signInManager = signInManager;
			_logger = logger;
		}

		public async Task OnGetAsync(string returnUrl = null) {
			await _signInManager.SignOutAsync();
			_logger.LogInformation("User logged out.");
		}
	}
}
