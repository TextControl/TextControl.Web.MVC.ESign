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
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace esign.Controllers {
	[Authorize]
	public class EnvelopeController : Controller {

		private readonly Credentials _credentials;
		private readonly string _userId;
		private readonly UserManager<LiteDB.Identity.Models.LiteDbUser> _userManager;
		private EnvelopeStore _store;

		public EnvelopeController(IOptions<Credentials> credentials, IHttpContextAccessor httpContextAccessor, UserManager<LiteDB.Identity.Models.LiteDbUser> userManager) {
			_credentials = credentials.Value;
			_userId = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
			_userManager = userManager;
			_store = new EnvelopeStore(_userId);
		}

		public IActionResult RequestSignature(string id) {
			// try to find the envelope id
			try {
				byte[] octets = Convert.FromBase64String(id);

				var structureFolder = System.Text.Encoding.ASCII.GetString(octets).Split(':');
				var _contractStorestore = new ContractStore(structureFolder[1]);

				Contract contract = _contractStorestore.GetContracts(structureFolder[0]).First();

				string document = _contractStorestore.GetDocument(contract.ContractID);
				string envelopeId = "";

				using (var ms = new MemoryStream(Convert.FromBase64String(document))) {
					envelopeId = EnvelopeDocument.ProcessNewDocument(ms,
						Guid.NewGuid().ToString() + ".tx",
						_store,
						_userManager.GetUserName(User),
						_userManager.GetUserId(User));
				}

				return RedirectToAction("create", "envelope", new { id = envelopeId });
			}
			catch {
				return RedirectToAction("External", "Review", new ReviewModel() { EnvelopeID = id, Error = true });
			}
		}

		[HttpPost]
		public IActionResult CreateNew(bool demo) {

			string envelopeId = "";
			string templateName = (demo == false) ? "newtemplate" : "demotemplate";

			byte[] newDocument= System.IO.File.ReadAllBytes("App_Data/" + templateName + ".tx");

			// create a stream from uploaded file
			using (var ms = new MemoryStream(newDocument)) {
				envelopeId = EnvelopeDocument.ProcessNewDocument(ms, 
					Guid.NewGuid().ToString() + ".tx",
					_store,
					_userManager.GetUserName(User),
					_userManager.GetUserId(User));
			}

			return Ok(envelopeId);
		}

		public IActionResult New() {

			// get files form submitted form
			var files = Request.Form.Files;
			string envelopeId = "";

			foreach (var file in files) {
				// create a stream from uploaded file
				using (var ms = new MemoryStream()) {
					file.CopyTo(ms);
					envelopeId = EnvelopeDocument.ProcessNewDocument(ms, 
						file.FileName,
						_store,
						_userManager.GetUserName(User),
						_userManager.GetUserId(User));
				}
			}

			return Ok(envelopeId);
		}

		[HttpGet]
		public IActionResult Document(string id) {
			// returns the stored original document
			string document = _store.GetDocument(id);

			TextControlHelpers tx = new TextControlHelpers(document);
			
			return Ok(Convert.ToBase64String(tx.ConditionToId(false)));
		}

		[HttpPost]
		public IActionResult Submit(string id) {

			// get envelope by id
			Envelope envelope = _store.GetEnvelopes(id).First();
			envelope.Status = EnvelopeStatus.Sent;
			envelope.Sent = DateTime.Now;

			// set the status to "sent"
			_store.Update(envelope.EnvelopeID, envelope);

			// send the confirmation e-mail
			ConfirmationEmail email = new ConfirmationEmail(_credentials);
			var host = Request.Scheme + "://" + Request.Host;
			email.SendConfirmationEmail(envelope, host, _userId);

			return Ok(envelope);
		}

		[HttpPost]
		public IActionResult SaveDocument([FromBody] SignModel document, string id) {

			Envelope envelope = _store.GetEnvelopes(id).First();

			byte[] sDocument;

			sDocument = Convert.FromBase64String(document.Document);
			byte[] thumbnail;

			// check if document contains signature boxes
			using (TextControlHelpers tx = new TextControlHelpers(Convert.ToBase64String(sDocument))) {
				envelope.ContainsSignatureBoxes = tx.ContainsSignatureBox(envelope.Signers);
				sDocument = tx.ConditionToId(true);
				thumbnail = tx.GetThumbnail();
			}

			// update the original file
			using (MemoryStream str = new MemoryStream(sDocument)) {
				_store.UpdateFile(envelope, str);
			}

			// update the thumbnail
			using (MemoryStream str = new MemoryStream(thumbnail)) {
				_store.AddThumbnail(envelope, str);
			}

			_store.Update(envelope.EnvelopeID, envelope);

			return Ok();
		}

		[HttpPost]
		public IActionResult UpdateRecipient([FromBody] Signer signer, string id) {

			Envelope envelope = _store.GetEnvelopes(id).First();

			if (envelope.Signers.Count != 0) {
				var query = envelope.Signers
							  .Where(p => p.Email.ToLower() == signer.Email.ToLower());

				if (query.Count() != 0)
					return BadRequest("List already contains this recipient.");
			}

			envelope.Signers.Add(new Signer() {
				Name = signer.Name,
				Email = signer.Email,
				Id = Guid.NewGuid().ToString()
			});

			envelope.Status = EnvelopeStatus.New;

			_store.Update(envelope.EnvelopeID, envelope);

			return Ok(envelope);	
		}

		[HttpGet]
		public IActionResult ReceiveRecipients(string id) {

			Envelope envelope = _store.GetEnvelopes(id).First();

			return Ok(envelope);
		}

		[HttpPost]
		public IActionResult RemoveRecipient([FromBody] Signer signer, string id) {

			Envelope envelope = _store.GetEnvelopes(id).First();

			var query = envelope.Signers
							  .Where(p => p.Email.ToLower() == signer.Email.ToLower());

			if (query.Count() == 0)
				return BadRequest();

			envelope.Signers.Remove(query.First());

			envelope.Status = EnvelopeStatus.New;

			_store.Update(envelope.EnvelopeID, envelope);

			return Ok(envelope);
		}

		public IActionResult Index() {
			return View(_store.GetEnvelopes());
		}

		public IActionResult Summary(string id) {

			List<Envelope> results = _store.GetEnvelopes(id);

			foreach (Signer signer in results[0].Signers) {
				if (signer.SignatureInformation != null) {
					signer.SignatureImage = _store.GetSignatureImage(id, signer.Id);
				}
			}

			var imageString = _store.GetThumbnail(id);

			// model contains the envelope and a thumbnail
			EditModel editModel = new EditModel() {
				Envelope = results[0],
				Image = imageString
			};

			return View(editModel);
		}

		public IActionResult Download(string id) {
			// returns the signed document
			string document = _store.GetFinalSignedDocument(id);
			return File(Convert.FromBase64String(document), "application/pdf");
		}

		public IActionResult Create(string id) {

			List<Envelope> results = _store.GetEnvelopes(id);

			var imageString = _store.GetThumbnail(id);

			EditModel editModel = new EditModel() {
				Envelope = results[0],
				Image = imageString
			};

			return View(editModel);
		}

	}
}
