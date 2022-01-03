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
	public class AgreementStore {

		private readonly string _userId;

		public AgreementStore(string userId) {
			_userId = userId;
		}

		public void Add(Agreement agreement, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/agreements_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Agreement>("agreement");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/agreements/" + agreement.AgreementID + "/original", agreement.AgreementID, stream);

				col.Insert(agreement);
			}
		}

		public string GetAgreement(string agreementId) {
			using (var db = new LiteDatabase(@"Filename=Data/agreements_" + _userId + ".db; Connection=shared")) {
				var fs = db.FileStorage;

				using (MemoryStream ms = new MemoryStream()) {
					fs.Download("$/agreements/" + agreementId + "/original", ms);
					var fileBytes = ms.ToArray();

					return Convert.ToBase64String(fileBytes);
				}
			}
		}

		public void Update(string agreementId, Agreement agreement) {
			using (var db = new LiteDatabase(@"Filename=Data/agreements_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Agreement>("agreement");

				col.Update(agreement);
			}
		}

		public string GetThumbnail(string agreementId) {
			using (var db = new LiteDatabase(@"Filename=Data/agreements_" + _userId + ".db; Connection=shared")) {
				var fs = db.FileStorage;

				using (MemoryStream ms = new MemoryStream()) {
					if (fs.Exists("$/agreements/" + agreementId + "/thumbnail") == true) {
						fs.Download("$/agreements/" + agreementId + "/thumbnail", ms);
						var fileBytes = ms.ToArray();
						return Convert.ToBase64String(fileBytes);
					}
					else
						return null;
				}
			}
		}

		public void AddThumbnail(Agreement agreement, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/agreements_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Agreement>("agreement");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/agreements/" + agreement.AgreementID + "/thumbnail", agreement.AgreementID, stream);
			}
		}

		public void UpdateFile(Agreement agreement, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/agreements_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Agreement>("agreement");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/agreements/" + agreement.AgreementID + "/original", agreement.AgreementID, stream);
			}
		}

		public string GetDocument(string agreementId) {
			using (var db = new LiteDatabase(@"Filename=Data/agreements_" + _userId + ".db; Connection=shared")) {
				var fs = db.FileStorage;

				using (MemoryStream ms = new MemoryStream()) {
					fs.Download("$/agreements/" + agreementId + "/original", ms);
					var fileBytes = ms.ToArray();

					return Convert.ToBase64String(fileBytes);
				}
			}
		}

		public List<Agreement> GetAgreements(string agreementId = null) {
			
			using (var db = new LiteDatabase(@"Filename=Data/agreements_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Agreement>("agreement");
				List<Agreement> results = null;

				if (agreementId == null) {
					results = col.Query().ToList();
				}
				else {
					results = col.Query()
						.Where(x => x.AgreementID == agreementId)
						.ToList();
				}

				return results;
			}
		}

	}
}
