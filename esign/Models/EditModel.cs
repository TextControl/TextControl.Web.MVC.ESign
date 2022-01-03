using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace esign.Models {
	public class EditModel {
		public string Image { get; set; }
		public Envelope Envelope { get; set; }
	}

	public class EditContractModel {
		public string Image { get; set; }
		public Contract Contract { get; set; }
	}

	public class EditTemplateModel {
		public string Image { get; set; }
		public Template Template { get; set; }
	}

	public class EditAgreementModel {
		public string Image { get; set; }
		public Agreement Agreement { get; set; }
	}

	public class TemplateEditModel {
		public string Document { get; set; }
		public Template Template { get; set; }
	}

	public class AgreementEditModel {
		public string Document { get; set; }
		public Agreement Template { get; set; }
	}

	public class SignModel {
		public string Document { get; set; }
		public Envelope Envelope { get; set; }
		public Signer Signer { get; set; }
	}

	public class CollaborationModel {
		public string Document { get; set; }
		public Contract Contract { get; set; }
		public string User { get; set; }
		public bool Owner{ get; set; }
	}
}
