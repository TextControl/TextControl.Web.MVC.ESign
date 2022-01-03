using esign.Helpers;
using esign.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace esign.Controllers {
	[Authorize]
	public class PartialController : Controller {

		private readonly UserManager<LiteDB.Identity.Models.LiteDbUser> _userManager;
		private EnvelopeStore _store;
		private TemplateStore _templateStore;
		private AgreementStore _agreementStore;
		private readonly string _userId;

		public PartialController(IHttpContextAccessor httpContextAccessor, UserManager<LiteDB.Identity.Models.LiteDbUser> userManager) {
			_userId = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
			_userManager = userManager;
		}

		public IActionResult EditTemplate(string id) {

			_templateStore = new TemplateStore(_userId);

			TemplateEditModel model = new TemplateEditModel() {
				Document = _templateStore.GetDocument(id),
				Template = _templateStore.GetTemplates(id).First()
			};

			return PartialView("_EditTemplate", model);
		}

		public IActionResult EditAgreement(string id) {

			_agreementStore = new AgreementStore(_userId);

			AgreementEditModel model = new AgreementEditModel() {
				Document = _agreementStore.GetDocument(id),
				Template = _agreementStore.GetAgreements(id).First()
			};

			return PartialView("_EditAgreement", model);
		}

		public IActionResult Edit(string id) {

			_store = new EnvelopeStore(_userId);

			SignModel model = new SignModel() {
				Document = _store.GetDocument(id),
				Envelope = _store.GetEnvelopes(id).First()
			};

			return PartialView("_Edit", model);
		}

		public IActionResult SignatureBox(string id) {

			_store = new EnvelopeStore(_userId);

			Envelope envelope = _store.GetEnvelopes(id).First();

			SignatureBoxModel model = new SignatureBoxModel() {
				ContainsSignatureBoxes = envelope.ContainsSignatureBoxes,
				EnvelopeID = envelope.EnvelopeID
			};

			return PartialView("_SignatureBox", model);
		}
	}
}
