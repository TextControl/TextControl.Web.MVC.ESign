using dsserverweb.Helpers;
using esign.Helpers;
using esign.Models;
using LiteDB;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace esign.Controllers {

	public class CollaborationController : Controller {

		private readonly Credentials _credentials;
		private readonly string _userId;

		public CollaborationController(IOptions<Credentials> credentials, IHttpContextAccessor httpContextAccessor) {
			_credentials = credentials.Value;
			_userId = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
		}

		public IActionResult Thanks() {
			return View();
		}

		[HttpPost]
		public IActionResult SaveDocument([FromBody] CollaborationModel document, string id, bool owner) {

			byte[] octets = Convert.FromBase64String(id);

			var structureFolder = System.Text.Encoding.ASCII.GetString(octets).Split(':');
			var _store = new ContractStore(structureFolder[1]);

			Contract contract = _store.GetContracts(structureFolder[0]).First();

			byte[] sDocument;

			sDocument = Convert.FromBase64String(document.Document);

			// udpate update the original file
			MemoryStream str = new MemoryStream(sDocument);
			_store.UpdateFile(contract, str);
			
			contract.Status = ContractStatus.Accepted;

			// check if document contains signature boxes
			using (TextControlHelpers tx = new TextControlHelpers(Convert.ToBase64String(sDocument))) {
				contract.HasTrackedChanges = tx.HasTrackedChanges();
				contract.Status = (contract.HasTrackedChanges == false) ? ContractStatus.Accepted : ContractStatus.Changed;
			}
			
			_store.Update(contract.ContractID, contract);

			// send the confirmation e-mail
			ConfirmationEmail email = new ConfirmationEmail(_credentials);
			var host = Request.Scheme + "://" + Request.Host;

			if (owner == true) {
				email.SendReviewEmail(contract, host, _userId);
			}
			else {
				email.SendReviewOwnerEmail(contract, host); // send e-mail
			}


			string returnUrl = (owner == true) ? "/contract/index/" : "/collaboration/thanks/";

			return Ok(returnUrl);
		}

		[HttpGet]
		public IActionResult Document(string id) {

			byte[] octets = Convert.FromBase64String(id);

			var structureFolder = System.Text.Encoding.ASCII.GetString(octets).Split(':');
			var _store = new ContractStore(structureFolder[1]);

			// returns the stored original document
			string document = _store.GetDocument(structureFolder[0]);
			return Ok(document);
		}

		public IActionResult Edit(string id) {
			// try to find the envelope id
			try {
				byte[] octets = Convert.FromBase64String(id);

				var structureFolder = System.Text.Encoding.ASCII.GetString(octets).Split(':');
				var _store = new ContractStore(structureFolder[1]);

				Contract contract = _store.GetContracts(structureFolder[0]).First();

				// cannot be signed twice
				if (contract.Status == ContractStatus.Closed ||
					contract.Status == ContractStatus.Accepted)
					return View("FullySigned");

				string document = _store.GetDocument(contract.ContractID);

				CollaborationModel model = new CollaborationModel() {
					Document = document,
					Contract = contract,
					User = contract.Signer.Email,
					Owner = false
				};

				return View(model);
			}
			catch {
				return RedirectToAction("External", "Review", new ReviewModel() { EnvelopeID = id, Error = true });
			}
		}
	}
}
