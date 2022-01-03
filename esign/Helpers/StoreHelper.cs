using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace esign.Helpers {

	public class StoreHelper {

		private readonly string _userId;

		public StoreHelper(string userId) {
			_userId = userId;
		}

		public void DeleteAllStores() {
			string[] files = Directory.GetFiles("Data", "*" + _userId + "*");

			foreach(string file in files) {
				File.Delete(file);
			}
		}

	}


}
