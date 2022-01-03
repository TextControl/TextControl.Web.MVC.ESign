using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace esign.Models
{
    public class ReviewModel
    {
      public string EnvelopeID { get; set; }
      public bool Error { get; set; }
   }

   public class ValidateModel {
      //public string EnvelopeID { get; set; }
      public IFormFile Document { get; set; }
      public bool Error { get; set; }
   }

   public class ValidatedDocument {
      public Envelope Envelope { get; set; }
      public bool Valid { get; set; }
   }

   public class ThanksModel {
      public Envelope Envelope { get; set; }
      public Signer Signer { get; set; }
   }
}
