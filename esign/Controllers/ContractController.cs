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
	public class ContractController : Controller {

		private readonly Credentials _credentials;
		private readonly string _userId;
		private readonly UserManager<LiteDB.Identity.Models.LiteDbUser> _userManager;
		private ContractStore _store;

		public ContractController(IOptions<Credentials> credentials, IHttpContextAccessor httpContextAccessor, UserManager<LiteDB.Identity.Models.LiteDbUser> userManager) {
			_credentials = credentials.Value;
			_userId = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
			_userManager = userManager;
			_store = new ContractStore(_userId);
		}

		public IActionResult Index() {
			return View(_store.GetContracts());
		}

		public IActionResult Create() {
			return View();
		}

		[HttpGet]
		public IActionResult Document(string id) {
			// returns the stored original document
			string document = _store.GetDocument(id);
			return Ok(document);
		}

		public IActionResult Edit(string id) {
			// try to find the envelope id
			try {
				byte[] octets = Convert.FromBase64String(id);

				var structureFolder = System.Text.Encoding.ASCII.GetString(octets).Split(':');
				var _store = new ContractStore(structureFolder[1]);

				Contract contract = _store.GetContracts(structureFolder[0]).First();

				string document = _store.GetDocument(contract.ContractID);

				CollaborationModel model = new CollaborationModel() {
					Document = document,
					Contract = contract,
					User = User.FindFirst(ClaimTypes.NameIdentifier).Value,
					Owner = true
				};

				return View("~/Views/collaboration/edit.cshtml", model);
			}
			catch {
				return RedirectToAction("External", "Review", new ReviewModel() { EnvelopeID = id, Error = true });
			}
		}

		public IActionResult Summary(string id) {

			List<Contract> results = _store.GetContracts(id);

			var imageString = _store.GetThumbnail(id);

			// model contains the envelope and a thumbnail
			EditContractModel editModel = new EditContractModel() {
				Contract = results[0],
				Image = imageString
			};

			return View(editModel);
		}

		[HttpPost]
		public IActionResult UpdateRecipient([FromBody] Signer signer, string id) {

			Contract contract = _store.GetContracts(id).First();

			contract.Signer = new Signer() {
				Name = signer.Name,
				Email = signer.Email,
				Id = Guid.NewGuid().ToString()
			};

			contract.Status = ContractStatus.New;

			_store.Update(contract.ContractID, contract);

			return Ok(contract);
		}

		[HttpPost]
		public IActionResult Submit(string id) {

			// get envelope by id
			Contract contract = _store.GetContracts(id).First();
			contract.Status = ContractStatus.Sent;
			contract.Sent = DateTime.Now;

			// set the status to "sent"
			_store.Update(contract.ContractID, contract);

			// send the confirmation e-mail
			ConfirmationEmail email = new ConfirmationEmail(_credentials);
			var host = Request.Scheme + "://" + Request.Host;
			email.SendReviewEmail(contract, host, _userId);

			return Ok(contract);
		}

		private NewContractModel ProcessNewDocument(MemoryStream ms, string Filename) {

			ms.Position = 0;
			byte[] image;
			byte[] data = ms.ToArray();

			// create thumbnail and check for signature boxes
			using (TextControlHelpers tx = new TextControlHelpers(Convert.ToBase64String(data))) {
				image = tx.GetThumbnail();
				ms = tx.GetInternalFormat();
			}

			// new Envelope object to be stored
			Contract contract = new Contract() {
				Created = DateTime.Now,
				Status = ContractStatus.New,
				Sender = _userManager.GetUserName(User),
				UserID = _userManager.GetUserId(User),
				Name = Filename,
				ContractID = Guid.NewGuid().ToString(),
			};

			_store.Add(contract, ms);

			using (var ms2 = new MemoryStream(image)) {
				_store.AddThumbnail(contract, ms2);
			}

			NewContractModel model = new NewContractModel() {
				Contract = contract,
				Thumbnail = Convert.ToBase64String(image)
			};

			return model;
		}

		[HttpPost]
		public IActionResult CreateNew() {

			NewContractModel contract = null;

			byte[] newDocument = System.IO.File.ReadAllBytes("App_Data/samplenda.tx");

			// create a stream from uploaded file
			using (var ms = new MemoryStream(newDocument)) {
				contract = ProcessNewDocument(ms, Guid.NewGuid().ToString() + ".tx");
			}

			return Ok(contract);
		}

		[HttpPost]
		public IActionResult New() {

			// get files form submitted form
			var files = Request.Form.Files;
			NewContractModel contract = null;

			foreach (var file in files) {
				// create a stream from uploaded file
				using (var ms = new MemoryStream()) {
					file.CopyTo(ms);
					contract = ProcessNewDocument(ms, file.FileName);
				}
			}

			return Ok(contract);
		}

	}
}
