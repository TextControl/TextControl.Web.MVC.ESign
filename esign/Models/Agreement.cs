using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace esign.Models {

	public class Agreement {
		public int Id { get; set; }
		public string AgreementID { get; set; } 
		public string UserID { get; set; }
		public string Name { get; set; }
		public DateTime Created { get; set; }
	}

	public class NewAgreementModel {
		public Agreement Agreement { get; set; }
		public string Thumbnail { get; set; }
	}

}
