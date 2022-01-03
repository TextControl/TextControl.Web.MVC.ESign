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
	public class TemplateController : Controller {

		private readonly Credentials _credentials;
		private IOptions<Credentials> _credentialOptions;
		private readonly string _userId;
		private readonly UserManager<LiteDB.Identity.Models.LiteDbUser> _userManager;
		private TemplateStore _store;
		private IHttpContextAccessor _httpContextAccessor;

		public TemplateController(IOptions<Credentials> credentials, IHttpContextAccessor httpContextAccessor, UserManager<LiteDB.Identity.Models.LiteDbUser> userManager) {
			_credentials = credentials.Value;
			_credentialOptions = credentials;
			_userId = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
			_userManager = userManager;
			_store = new TemplateStore(_userId);
			_httpContextAccessor = httpContextAccessor;
		}

		public IActionResult Create() {
			return View();
		}

		public IActionResult Summary(string id) {

			List<Template> results = _store.GetTemplates(id);

			var imageString = _store.GetThumbnail(id);

			// model contains the envelope and a thumbnail
			EditTemplateModel editModel = new EditTemplateModel() {
				Template = results[0],
				Image = imageString
			};

			return View(editModel);
		}

		public IActionResult Index() {
			return View(_store.GetTemplates());
		}

		private NewTemplateModel ProcessNewDocument(MemoryStream ms, string Filename) {

			ms.Position = 0;
			byte[] image;
			byte[] data = ms.ToArray();

			// create thumbnail and check for signature boxes
			using (TextControlHelpers tx = new TextControlHelpers(Convert.ToBase64String(data))) {
				image = tx.GetThumbnail();
				ms = tx.GetInternalFormat();
			}

			// new Envelope object to be stored
			Template template = new Template() {
				Created = DateTime.Now,
				UserID = _userManager.GetUserId(User),
				Name = Filename,
				TemplateID = Guid.NewGuid().ToString(),
			};

			_store.Add(template, ms);

			using (var ms2 = new MemoryStream(image)) {
				_store.AddThumbnail(template, ms2);
			}

			NewTemplateModel model = new NewTemplateModel() {
				Template = template,
				Thumbnail = Convert.ToBase64String(image)
			};

			return model;
		}

		[HttpPost]
		public IActionResult CreateNew() {

			NewTemplateModel template = null;

			byte[] newDocument = System.IO.File.ReadAllBytes("App_Data/newtemplate.tx");

			// create a stream from uploaded file
			using (var ms = new MemoryStream(newDocument)) {
				template = ProcessNewDocument(ms, Guid.NewGuid().ToString() + ".tx");
			}

			return Ok(template);
		}

		[HttpGet]
		public IActionResult Document(string id) {
			// returns the stored original document
			string document = _store.GetDocument(id);

			TextControlHelpers tx = new TextControlHelpers(document);

			return Ok(Convert.ToBase64String(tx.ConditionToId(false)));
		}

		[HttpPost]
		public IActionResult SaveDocument([FromBody] SignModel document, string id) {

			Template template = _store.GetTemplates(id).First();

			byte[] sDocument;

			sDocument = Convert.FromBase64String(document.Document);

			// udpate update the original file
			MemoryStream str = new MemoryStream(sDocument);
			_store.UpdateFile(template, str);

			// check if document contains signature boxes
			using (TextControlHelpers tx = new TextControlHelpers(Convert.ToBase64String(sDocument))) {
				sDocument = tx.ConditionToId(true);
			}

			_store.Update(template.TemplateID, template);

			return Ok();
		}

		[HttpPost]
		public IActionResult New() {

			// get files form submitted form
			var files = Request.Form.Files;
			NewTemplateModel template = null;

			foreach (var file in files) {
				// create a stream from uploaded file
				using (var ms = new MemoryStream()) {
					file.CopyTo(ms);
					template = ProcessNewDocument(ms, file.FileName);
				}
			}

			return Ok(template);
		}

		public IActionResult Instance(string id) {

			// get form fields 
			string json = "{";
			int counter = 0;

			foreach (string s in Request.Form.Keys) {
				if (counter != 0)
					json += ",";

				json += "\"" + s + "\":\"" + Request.Form[s] + "\"";
				counter++;
			}

			json += "}";

			Template template = _store.GetTemplates(id).First();
			
			string sDocument = _store.GetDocument(id);
			MemoryStream data;

			// check if document contains signature boxes
			using (TextControlHelpers tx = new TextControlHelpers(sDocument)) {
				data = tx.MergeJson(json);
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
		public IActionResult GetFields(string id) {

			string sDocument = _store.GetDocument(id);

			List<FieldModel> fields = new List<FieldModel>();

			// check if document contains signature boxes
			using (TextControlHelpers tx = new TextControlHelpers(sDocument)) {
				fields = tx.GetMergeFields();
			}

			return Ok(fields);
		}

	}
}
