using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace esign.Models {
	public class Template {
		public int Id { get; set; }
		public string TemplateID { get; set; } 
		public string UserID { get; set; }
		public string Name { get; set; }
		public DateTime Created { get; set; }
		public bool ContainsSignatureBoxes { get; set; }
	}

	public class NewTemplateModel {
		public Template Template { get; set; }
		public string Thumbnail { get; set; }
	}
}
