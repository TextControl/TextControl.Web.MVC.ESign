using esign.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace esign.Helpers {
	public static class EnvelopeDocument {
		public static string ProcessNewDocument(MemoryStream ms, string Filename, EnvelopeStore Store, string UserName, string UserId) {

			ms.Position = 0;
			byte[] image;
			byte[] data = ms.ToArray();
			bool bContainsSignatureBoxes;

			// create thumbnail and check for signature boxes
			using (TextControlHelpers tx = new TextControlHelpers(Convert.ToBase64String(data))) {
				image = tx.GetThumbnail();
				bContainsSignatureBoxes = false;
				ms = tx.GetInternalFormat();
			}

			// new Envelope object to be stored
			Envelope envelope = new Envelope() {
				Created = DateTime.Now,
				Status = EnvelopeStatus.Incomplete,
				Sender = UserName,
				UserID = UserId,
				Name = Filename,
				EnvelopeID = Guid.NewGuid().ToString(),
				ContainsSignatureBoxes = bContainsSignatureBoxes
			};

			Store.Add(envelope, ms);

			using (var ms2 = new MemoryStream(image)) {
				Store.AddThumbnail(envelope, ms2);
			}

			return envelope.EnvelopeID;
		}
	}
}
