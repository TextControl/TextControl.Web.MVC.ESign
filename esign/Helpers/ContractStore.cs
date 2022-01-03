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
	public class ContractStore {

		private readonly string _userId;

		public ContractStore(string userId) {
			_userId = userId;
		}

		public void Add(Contract contract, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/contracts_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Contract>("contract");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/contracts/" + contract.ContractID + "/original", contract.ContractID, stream);

				stream.Position = 0;
				fs.Upload("$/contracts/" + contract.ContractID + "/modified", contract.ContractID, stream);

				col.Insert(contract);
			}
		}

		public string GetThumbnail(string contractId) {
			using (var db = new LiteDatabase(@"Filename=Data/contracts_" + _userId + ".db; Connection=shared")) {
				var fs = db.FileStorage;

				using (MemoryStream ms = new MemoryStream()) {
					if (fs.Exists("$/contracts/" + contractId + "/thumbnail") == true) {
						fs.Download("$/contracts/" + contractId + "/thumbnail", ms);
						var fileBytes = ms.ToArray();
						return Convert.ToBase64String(fileBytes);
					}
					else
						return null;
				}
			}
		}

		public void UpdateFile(Contract contract, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/contracts_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Contract>("contract");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/contracts/" + contract.ContractID + "/modified", contract.ContractID, stream);
			}
		}

		public string GetDocument(string contractId) {
			using (var db = new LiteDatabase(@"Filename=Data/contracts_" + _userId + ".db; Connection=shared")) {
				var fs = db.FileStorage;

				using (MemoryStream ms = new MemoryStream()) {
					fs.Download("$/contracts/" + contractId + "/modified", ms);
					var fileBytes = ms.ToArray();

					return Convert.ToBase64String(fileBytes);
				}
			}
		}

		public void AddThumbnail(Contract contract, MemoryStream stream) {
			using (var db = new LiteDatabase(@"Filename=Data/contracts_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Contract>("contract");

				// upload document to db
				var fs = db.FileStorage;
				stream.Position = 0;
				fs.Upload("$/contracts/" + contract.ContractID + "/thumbnail", contract.ContractID, stream);
			}
		}

		public void Update(string contractId, Contract contract) {
			using (var db = new LiteDatabase(@"Filename=Data/contracts_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Contract>("contract");

				col.Update(contract);
			}
		}

		public List<Contract> GetContracts(string contractId = null) {
			
			using (var db = new LiteDatabase(@"Filename=Data/contracts_" + _userId + ".db; Connection=shared")) {
				var col = db.GetCollection<Contract>("contract");
				List<Contract> results = null;

				if (contractId == null) {
					results = col.Query().ToList();
				}
				else {
					results = col.Query()
						.Where(x => x.ContractID == contractId)
						.ToList();
				}

				return results;
			}
		}

	}
}
