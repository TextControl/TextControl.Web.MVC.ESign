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
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using TXTextControl.Web.MVC.DocumentViewer.Models;

namespace esign.Controllers {

	public class ReviewController : Controller {

		private readonly Credentials _credentials;
		private readonly string _userId;

		public ReviewController(IOptions<Credentials> credentials, IHttpContextAccessor httpContextAccessor) {
			_credentials = credentials.Value;
			_userId = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
		}

		public IActionResult Sign(string id) {

			// try to find the envelope id
			try {
				byte[] octets = Convert.FromBase64String(id);

				var structureFolder = System.Text.Encoding.ASCII.GetString(octets).Split(':');
				var _store = new EnvelopeStore(structureFolder[1]);

				Envelope envelope = _store.GetEnvelopes(structureFolder[0]).First();
				Signer currentSigner = null; 

				foreach (Signer signer in envelope.Signers) {
					if (signer.Id == structureFolder[2])
						currentSigner = signer;
				}

				// cannot be signed twice
				if (currentSigner.SignatureInformation != null)
					return View("FullySigned");

				currentSigner.SignerStatus = SignerStatus.Opened;

				_store.Update(envelope.EnvelopeID, envelope);

				string document = _store.GetDocument(envelope.EnvelopeID);

				TextControlHelpers tx = new TextControlHelpers(document);
				byte[] preparedDocument = tx.PrepareFormFields(currentSigner);

				SignModel model = new SignModel() {
					Document = Convert.ToBase64String(preparedDocument),
					Envelope = envelope,
					Signer = currentSigner
				};

				return View(model);
			}
			catch {
				return RedirectToAction("External", "Review", new ReviewModel() { EnvelopeID = id, Error = true });
			}

		}
		
		[HttpPost]
		public IActionResult ExternalLink(ReviewModel review) {
			return RedirectToAction("Sign", "Review", new { id = review.EnvelopeID });
		}

		public IActionResult External(ReviewModel model) {
			return View(model);
		}

		[HttpPost]
		public IActionResult ValidateDocument(ValidateModel validate) {

			// try to find the document
			using (var ms = new MemoryStream()) {
				validate.Document.CopyTo(ms);

				TextControlHelpers tx = new TextControlHelpers();
				string accessId = tx.GetDocumentAccessId(ms.ToArray());

				byte[] octets;

				try {
					octets = Convert.FromBase64String(accessId);
				}
				catch {
					return RedirectToAction("Validate", "Review", new ValidateModel() { Error = true });
				}

				var structureFolder = System.Text.Encoding.ASCII.GetString(octets).Split(':');
				var _store = new EnvelopeStore(structureFolder[1]);

				if (_store.GetEnvelopes(structureFolder[0]).Count == 0)
					return RedirectToAction("Validate", "Review", new ValidateModel() { Error = true });

				Envelope envelope = _store.GetEnvelopes(structureFolder[0])?.First();

				// must be fully signed!
				if (envelope == null || envelope.Status != EnvelopeStatus.Signed)
					return RedirectToAction("Validate", "Review", new ValidateModel() { Error = true });

				var storedDocument = _store.GetFinalSignedDocument(envelope.EnvelopeID);

				// create MD5 checksum values to compare
				string storedMD5 = EnvelopeStore.CalculateMD5(Convert.FromBase64String(storedDocument));
				string uploadedMD5 = EnvelopeStore.CalculateMD5(ms.ToArray());

				// compare the values
				bool valid = (storedMD5 == uploadedMD5) ? true : false;

				ValidatedDocument validDocument = new ValidatedDocument() {
					Envelope = envelope,
					Valid = valid
				};

				return View(validDocument);
			}
		}

		public IActionResult Validate(ValidateModel model) {
			return View(model);
		}

		public IActionResult Thanks(string id) {
			byte[] octets = Convert.FromBase64String(id);

			var structureFolder = System.Text.Encoding.ASCII.GetString(octets).Split(':');
			var _store = new EnvelopeStore(structureFolder[1]);

			Envelope envelope = _store.GetEnvelopes(structureFolder[0]).First();
			Signer currentSigner = null;

			foreach(Signer signer in envelope.Signers) {
				if (signer.Id == structureFolder[2])
					currentSigner = signer;
			}

			ThanksModel model = new ThanksModel() { 
				Envelope = envelope,
				Signer = currentSigner
			};

			return View(model);
		}

		[HttpPost]
		public IActionResult SignDocumentFinal([FromBody] SignatureData data, string userID, string envelopeId, string signerId) {

			var _store = new EnvelopeStore(userID);

			Envelope envelope = _store.GetEnvelopes(envelopeId).First();

			Signer currentSigner = null;

			foreach (Signer signer in envelope.Signers) {
				if (signer.Id == signerId)
					currentSigner = signer;
			}

			// get IP address 
			currentSigner.SignatureInformation = new SignatureModel()
			{
				Document = data.SignedDocument.Document,
				IPAddress = Request.HttpContext.Connection.RemoteIpAddress.ToString(),
				NumPages = data.SignedDocument.NumPages,
				SignerInitials = data.SignedDocument.SignerInitials,
				SignerName = data.SignedDocument.SignerName,
				TimeStamp = data.SignedDocument.TimeStamp,
				UniqueId = data.SignedDocument.UniqueId
			};

			// update DB
			_store.Update(envelope.EnvelopeID, envelope);

			byte[] signedDocument = Convert.FromBase64String(data.SignedDocument.Document);

			using (var ms = new MemoryStream(signedDocument)) {
				_store.UploadSignedDocument(envelope, ms, signerId);
			}

			byte[] signatureImage = Convert.FromBase64String(data.SignatureImage);

			using (var ms = new MemoryStream(signatureImage)) {
				_store.UploadSignatureImage(envelope, ms, signerId);
			}

			ConfirmationEmail email = new ConfirmationEmail(_credentials);
			var host = Request.Scheme + "://" + Request.Host;
			email.SendSignedEmail(envelope, currentSigner);

			bool fullySigned = true;
			currentSigner.SignerStatus = SignerStatus.Signed;

			foreach (Signer signer in envelope.Signers) {
				if (signer.SignerStatus != SignerStatus.Signed)
					fullySigned = false;
			}

			if (fullySigned == true) { 

				envelope.Status = EnvelopeStatus.Signed;
				string masterDocument;
				List<string> signedDocuments = null;

				if (envelope.Signers.Count > 1) {
					masterDocument = _store.GetDocument(envelopeId);
					signedDocuments = new List<string>();

					foreach (Signer signer in envelope.Signers) {
						signedDocuments.Add(_store.GetSignedDocument(envelopeId, signer.Id));
					}
				}
				else {
					masterDocument = _store.GetSignedDocument(envelopeId, envelope.Signers[0].Id);
				}

				TextControlHelpers tx = new TextControlHelpers(masterDocument);
				List<byte[]> createdPDF = tx.CreatePDF(envelope, envelope.UserID, signedDocuments);

				using (var ms = new MemoryStream(createdPDF[1])) {
					_store.AddThumbnail(envelope, ms);
				}

				using (var ms = new MemoryStream(createdPDF[0])) {
					_store.UploadFinalSignedDocument(envelope, ms);

					foreach (Signer signer in envelope.Signers) {
						// send the confirmation e-mail
						email.SendFinalSignedEmail(envelope, ms, signer);
					}
					
				}

			}

			_store.Update(envelope.EnvelopeID, envelope);

			return Ok(true);			
		}

	}
}
