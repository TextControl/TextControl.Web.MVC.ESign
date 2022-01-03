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
	public class AgreementController : Controller {

		private readonly Credentials _credentials;
		private IOptions<Credentials> _credentialOptions;
		private readonly string _userId;
		private readonly UserManager<LiteDB.Identity.Models.LiteDbUser> _userManager;
		private readonly SignInManager<LiteDB.Identity.Models.LiteDbUser> _signInManager;
		private AgreementStore _store;
		private IHttpContextAccessor _httpContextAccessor;

		public AgreementController(IOptions<Credentials> credentials, IHttpContextAccessor httpContextAccessor, UserManager<LiteDB.Identity.Models.LiteDbUser> userManager, SignInManager<LiteDB.Identity.Models.LiteDbUser> signInManager) {
			_credentials = credentials.Value;
			_credentialOptions = credentials;
			_userId = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
			_userManager = userManager;
			_signInManager = signInManager;
			_store = new AgreementStore(_userId);
			_httpContextAccessor = httpContextAccessor;
		}

		public IActionResult Create() {
			return View();
		}

		public IActionResult Index() {
			return View(_store.GetAgreements());
		}

		public void AddThumbnail(Agreement agreement, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/agreements_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Template>("agreement");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/agreements_/" + agreement.AgreementID + "/thumbnail", agreement.AgreementID, stream);
			}
		}
		[Authorize]
		public IActionResult Summary(string id) {

			List<Agreement> results = _store.GetAgreements(id);

			var imageString = _store.GetThumbnail(id);

			// model contains the envelope and a thumbnail
			EditAgreementModel editModel = new EditAgreementModel() {
				Agreement = results[0],
				Image = imageString
			};

			return View(editModel);
		}

		[HttpPost]
		public IActionResult CreateNew(bool sample) {

			NewAgreementModel agreement = null;
			byte[] newDocument = null;

			if (sample == false)
				newDocument = System.IO.File.ReadAllBytes("App_Data/newtemplate.tx");
			else
				newDocument = System.IO.File.ReadAllBytes("App_Data/samplenda-agreement.tx");

			// create a stream from uploaded file
			using (var ms = new MemoryStream(newDocument)) {
				agreement = ProcessNewDocument(ms, Guid.NewGuid().ToString() + ".tx");
			}

			return Ok(agreement);
		}

		[HttpPost]
		public IActionResult SaveDocument([FromBody] SignModel document, string id) {

			Agreement template = _store.GetAgreements(id).First();

			byte[] sDocument;

			sDocument = Convert.FromBase64String(document.Document);

			// udpate update the original file
			MemoryStream str = new MemoryStream(sDocument);
			_store.UpdateFile(template, str);

			return Ok();
		}
		[Authorize]
		public IActionResult Instance(string id) {

			string sDocument = _store.GetAgreement(id);
			MemoryStream data;

			Agreement template = _store.GetAgreements(id).First();

			using (TextControlHelpers tx = new TextControlHelpers(sDocument)) {
				data = tx.GenerateAgreement(Request.Form.Keys.ToList());
			}

			EnvelopeStore store = new EnvelopeStore(_userId);

			string documentId = EnvelopeDocument.ProcessNewDocument(data,
				template.Name,
				store,
				_userManager.GetUserName(User),
				_userManager.GetUserId(User));

			return RedirectToAction("create", "envelope", new { id = documentId });
		}

		[HttpPost]
		public IActionResult GetSections(string id) {

			string sDocument = _store.GetDocument(id);

			List<SectionModel> sections = new List<SectionModel>();

			// check if document contains signature boxes
			using (TextControlHelpers tx = new TextControlHelpers(sDocument)) {
				sections = tx.GetSubTextParts();
			}

			return Ok(sections);
		}

		[HttpPost]
		public IActionResult New() {

			// get files form submitted form
			var files = Request.Form.Files;
			NewAgreementModel agreement = null;

			foreach (var file in files) {
				// create a stream from uploaded file
				using (var ms = new MemoryStream()) {
					file.CopyTo(ms);
					agreement = ProcessNewDocument(ms, file.FileName);
				}
			}

			return Ok(agreement);
		}

		private NewAgreementModel ProcessNewDocument(MemoryStream ms, string Filename) {

			ms.Position = 0;
			byte[] image;
			byte[] data = ms.ToArray();

			// create thumbnail and check for signature boxes
			using (TextControlHelpers tx = new TextControlHelpers(Convert.ToBase64String(data))) {
				image = tx.GetThumbnail();
				ms = tx.GetInternalFormat();
			}

			// new Envelope object to be stored
			Agreement agreement = new Agreement() {
				Created = DateTime.Now,
				UserID = _userManager.GetUserId(User),
				Name = Filename,
				AgreementID = Guid.NewGuid().ToString(),
			};

			_store.Add(agreement, ms);

			using (var ms2 = new MemoryStream(image)) {
				_store.AddThumbnail(agreement, ms2);
			}

			NewAgreementModel model = new NewAgreementModel() {
				Agreement = agreement,
				Thumbnail = Convert.ToBase64String(image)
			};

			return model;
		}

	}
}
