using esign.Helpers;
using esign.Models;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace esign.ActionFilter {
	public class OpenedMiddleware {
		private RequestDelegate m_next;
		private string openedId;
		

		public OpenedMiddleware(RequestDelegate next) {
			m_next = next;
		}

		public async Task Invoke(HttpContext context) {

			// check, if request is a TX Text Control WebSocket request
			if (context.Request.Query["opened"] != "") { 
				openedId = context.Request.Query["opened"];

				if (openedId != null) {

					byte[] octets = Convert.FromBase64String(openedId);

					var structureFolder = System.Text.Encoding.ASCII.GetString(octets).Split(':');
					var _store = new EnvelopeStore(structureFolder[1]);

					var envelope = _store.GetEnvelopes(structureFolder[0])[0];

					foreach (Signer signer in envelope.Signers) {
						if (signer.Id == structureFolder[2]) { 
							signer.SignerStatus = SignerStatus.Received;
						}
					}

					_store.Update(envelope.EnvelopeID, envelope);
				}

				await m_next.Invoke(context);
			}
			else if (m_next != null) {
				await m_next.Invoke(context);
			}
		}
	}
}
