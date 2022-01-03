using esign.Models;
using LiteDB;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace esign.Helpers {
	public class TemplateStore {

		private readonly string _userId;

		public TemplateStore(string userId) {
			_userId = userId;
		}

		public void Add(Template template, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/templates_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Template>("template");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/templates/" + template.TemplateID + "/original", template.TemplateID, stream);

				col.Insert(template);
			}
		}

		public string GetThumbnail(string templateId) {
			using (var db = new LiteDatabase(@"Filename=Data/templates_" + _userId + ".db; Connection=shared")) {
				var fs = db.FileStorage;

				using (MemoryStream ms = new MemoryStream()) {
					if (fs.Exists("$/templates/" + templateId + "/thumbnail") == true) {
						fs.Download("$/templates/" + templateId + "/thumbnail", ms);
						var fileBytes = ms.ToArray();
						return Convert.ToBase64String(fileBytes);
					}
					else
						return null;
				}
			}
		}

		public void UpdateFile(Template template, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/templates_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Template>("template");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/templates/" + template.TemplateID + "/original", template.TemplateID, stream);
			}
		}

		public string GetDocument(string templateId) {
			using (var db = new LiteDatabase(@"Filename=Data/templates_" + _userId + ".db; Connection=shared")) {
				var fs = db.FileStorage;

				using (MemoryStream ms = new MemoryStream()) {
					fs.Download("$/templates/" + templateId + "/original", ms);
					var fileBytes = ms.ToArray();

					return Convert.ToBase64String(fileBytes);
				}
			}
		}

		public void AddThumbnail(Template template, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/templates_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Template>("template");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/templates/" + template.TemplateID + "/thumbnail", template.TemplateID, stream);
			}
		}

		public void Update(string templateId, Template template) {
			using (var db = new LiteDatabase(@"Filename=Data/templates_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Template>("template");

				col.Update(template);
			}
		}

		public List<Template> GetTemplates(string templateId = null) {
			
			using (var db = new LiteDatabase(@"Filename=Data/templates_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Template>("template");
				List<Template> results = null;

				if (templateId == null) {
					results = col.Query().ToList();
				}
				else {
					results = col.Query()
						.Where(x => x.TemplateID == templateId)
						.ToList();
				}

				return results;
			}
		}

	}
}
