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
	public class EnvelopeStore {

		private readonly string _userId;

		public EnvelopeStore(string userId) {
			_userId = userId;
		}

		public static string CalculateMD5(byte[] document) {
			using (var md5 = MD5.Create()) {
				return BitConverter.ToString(md5.ComputeHash(document)).Replace("-", "").ToLower();
			}
		}

		public void Add(Envelope envelope, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Envelope>("envelope");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/envelopes/" + envelope.EnvelopeID + "/original", envelope.EnvelopeID, stream);

				col.Insert(envelope);
			}
		}

		public void UploadSignedDocument(Envelope envelope, MemoryStream stream, string signerId) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Envelope>("envelope");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/envelopes/" + envelope.EnvelopeID + "/signed/" + signerId, envelope.EnvelopeID, stream);
			}
		}

		public void UploadSignatureImage(Envelope envelope, MemoryStream stream, string signerId) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Envelope>("envelope");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/envelopes/" + envelope.EnvelopeID + "/signatures/" + signerId, envelope.EnvelopeID, stream);
			}
		}

		public string GetSignatureImage(string envelopeId, string signerId) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var fs = db.FileStorage;

				using (MemoryStream ms = new MemoryStream()) {
					fs.Download("$/envelopes/" + envelopeId + "/signatures/" + signerId, ms);
					var fileBytes = ms.ToArray();
					return Convert.ToBase64String(fileBytes);
				}
			}
		}

		public string GetSignedDocument(string envelopeId, string signerId) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var fs = db.FileStorage;

				using (MemoryStream ms = new MemoryStream()) {
					fs.Download("$/envelopes/" + envelopeId + "/signed/" + signerId, ms);
					var fileBytes = ms.ToArray();
					return Convert.ToBase64String(fileBytes);
				}
			}
		}

		public void UploadFinalSignedDocument(Envelope envelope, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Envelope>("envelope");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/envelopes/" + envelope.EnvelopeID + "/final", envelope.EnvelopeID, stream);
			}
		}

		public void UpdateFile(Envelope envelope, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Envelope>("envelope");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/envelopes/" + envelope.EnvelopeID + "/original", envelope.EnvelopeID, stream);
			}
		}

		public void Update(string envelopeId, Envelope envelope) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Envelope>("envelope");

				col.Update(envelope);
			}
		}

		public void AddThumbnail(Envelope envelope, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Envelope>("envelope");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/envelopes/" + envelope.EnvelopeID + "/thumbnail", envelope.EnvelopeID, stream);
			}
		}

		public void Delete(Envelope envelope) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Envelope>("envelope");
				col.Insert(envelope);
			}
		}

		public string GetDocument(string envelopeId) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var fs = db.FileStorage;

				using (MemoryStream ms = new MemoryStream()) { 
					fs.Download("$/envelopes/" + envelopeId + "/original", ms);
					var fileBytes = ms.ToArray();

					return Convert.ToBase64String(fileBytes);
				}
			}
		}

		public string GetFinalSignedDocument(string envelopeId) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var fs = db.FileStorage;

				using (MemoryStream ms = new MemoryStream()) {
					fs.Download("$/envelopes/" + envelopeId + "/final", ms);
					var fileBytes = ms.ToArray();
					return Convert.ToBase64String(fileBytes);
				}
			}
		}

		public string GetThumbnail(string envelopeId) {
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var fs = db.FileStorage;

				using (MemoryStream ms = new MemoryStream()) {
					if (fs.Exists("$/envelopes/" + envelopeId + "/thumbnail") == true) {
						fs.Download("$/envelopes/" + envelopeId + "/thumbnail", ms);
						var fileBytes = ms.ToArray();
						return Convert.ToBase64String(fileBytes);
					}
					else
						return null;
				}
			}
		}

		public List<Envelope> GetEnvelopes(string envelopeId = null) {
			
			using (var db = new LiteDatabase(@"Filename=Data/envelopes_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Envelope>("envelope");
				List<Envelope> results = null;

				if (envelopeId == null) {
					results = col.Query().ToList();
				}
				else {
					results = col.Query()
						.Where(x => x.EnvelopeID == envelopeId)
						.ToList();
				}

				return results;
			}
		}

	}
}
