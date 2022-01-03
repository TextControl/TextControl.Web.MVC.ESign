using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace esign.Models {

	public class SignedDocumentModel {
		public SignatureModel SignatureModel { get; set; }
		public Envelope Envelope { get; set; }
		public string SignerId { get; set; }
		public string SignatureImage { get; set; }
	}

	public class SignatureModel {
		public string Document { get; set; }
		public int NumPages { get; set; }
		public string SignerInitials { get; set; }
		public string SignerName { get; set; }
		public DateTime TimeStamp { get; set; }
		public string UniqueId { get; set; }
		public string IPAddress { get; set; }

	}
}