using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;

namespace ActionFilters.ActionFilters {
   public class ValidationFilterAttribute : IActionFilter {


		private readonly UserManager<LiteDB.Identity.Models.LiteDbUser> _userManager;
		private readonly SignInManager<LiteDB.Identity.Models.LiteDbUser> _signInManager;

		public ValidationFilterAttribute(UserManager<LiteDB.Identity.Models.LiteDbUser> userManager, SignInManager<LiteDB.Identity.Models.LiteDbUser> signInManager) {
			_userManager = userManager;
			_signInManager = signInManager;
		}

		public void OnActionExecuting(ActionExecutingContext context) {
			
			if (context.HttpContext.User.Identity.IsAuthenticated == false) {
				var dummyEmail = Guid.NewGuid().ToString();

				var user = new LiteDB.Identity.Models.LiteDbUser { UserName = dummyEmail, Email = dummyEmail };
				var result = _userManager.CreateAsync(user, "Esign#2021").Result;

				var signedIn = _signInManager.PasswordSignInAsync(dummyEmail, "Esign#2021", true, lockoutOnFailure: false).Result;

				context.Result = new RedirectResult(context.HttpContext.Request.Path);
				return;

			}
		}
      public void OnActionExecuted(ActionExecutedContext context) {

      }
   }
}