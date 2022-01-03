using esign.Helpers;
using esign.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace dsserverweb.Helpers {
	public class ConfirmationEmail {

		private readonly Credentials _credentials;

		public ConfirmationEmail(Credentials credentials) {
			_credentials = credentials;
		}

		public void SendConfirmationEmail(Envelope envelope, string host, string userId) {
			// send e-mail
			EmailService emailService = new EmailService(_credentials);
			

			foreach (Signer signer in envelope.Signers) {

				string emailBody = System.IO.File.ReadAllText("App_Data/confirmation.html");

				byte[] octets = System.Text.Encoding.ASCII.GetBytes(envelope.EnvelopeID + ":" + userId + ":" + signer.Id);
				var envelope_code = Convert.ToBase64String(octets);

				emailBody = emailBody.Replace("%%%sender_name%%%", envelope.Sender);
				emailBody = emailBody.Replace("%%%envelope_code%%%", envelope_code);
				emailBody = emailBody.Replace("%%%url%%%", host);

				emailService.Send(new EmailMessage() {
					Body = emailBody,
					Destination = signer.Email,
					Subject = "Please sign: " + envelope.Name
				});

				signer.SignerStatus = SignerStatus.Sent;
			}
			
		}

		public void SendReviewOwnerEmail(Contract contract, string host) {
			// send e-mail
			EmailService emailService = new EmailService(_credentials);
			string emailBody = System.IO.File.ReadAllText("App_Data/reviewed.html");

			emailBody = emailBody.Replace("%%%signer_name%%%", contract.Sender);
			emailBody = emailBody.Replace("%%%url%%%", host);

			emailService.Send(new EmailMessage() {
				Body = emailBody,
				Destination = contract.Signer.Email,
				Subject = "Your document has been reviewed: " + contract.Name
			});
		}

		public void SendReviewEmail(Contract contract, string host, string userId) {
			// send e-mail
			EmailService emailService = new EmailService(_credentials);
			string emailBody = System.IO.File.ReadAllText("App_Data/confirmation-contract.html");

			byte[] octets = System.Text.Encoding.ASCII.GetBytes(contract.ContractID + ":" + userId);
			var envelope_code = Convert.ToBase64String(octets);

			emailBody = emailBody.Replace("%%%sender_name%%%", contract.Sender);
			emailBody = emailBody.Replace("%%%envelope_code%%%", envelope_code);
			emailBody = emailBody.Replace("%%%url%%%", host);

			emailService.Send(new EmailMessage() {
				Body = emailBody,
				Destination = contract.Signer.Email,
				Subject = "Please review: " + contract.Name
			});
		}

		public void SendFinalSignedEmail(Envelope envelope, MemoryStream stream, Signer signer) {
			// send e-mail
			EmailService emailService = new EmailService(_credentials);
			string emailBody = System.IO.File.ReadAllText("App_Data/signing-thanks_completed.html");

			emailBody = emailBody.Replace("%%%sender_name%%%", envelope.Sender);
			emailBody = emailBody.Replace("%%%envelope_id%%%", envelope.EnvelopeID);
			emailBody = emailBody.Replace("%%%document_name%%%", envelope.Name);

			stream.Position = 0;

			emailService.Send(new EmailMessage() {
				Body = emailBody,
				Destination = signer.Email,
				Subject = "Thanks for signing the document \"" + envelope.Name + "\"",
				Attachments = new List<System.Net.Mail.Attachment>() {
					new System.Net.Mail.Attachment(stream, Path.GetFileNameWithoutExtension(envelope.Name) + ".pdf", "application/pdf")
				}
			});
		}

		public void SendSignedEmail(Envelope envelope, Signer signer) {
			// send e-mail
			EmailService emailService = new EmailService(_credentials);
			string emailBody = System.IO.File.ReadAllText("App_Data/signing-thanks.html");

			emailBody = emailBody.Replace("%%%sender_name%%%", envelope.Sender);
			emailBody = emailBody.Replace("%%%envelope_id%%%", envelope.EnvelopeID);
			emailBody = emailBody.Replace("%%%document_name%%%", envelope.Name);

			emailService.Send(new EmailMessage() {
				Body = emailBody,
				Destination = signer.Email,
				Subject = "Thanks for signing the document \"" + envelope.Name + "\""
			});
		}

		public void SendConfirmationOwnerEmail(Envelope envelope, string host) {
			// send e-mail
			EmailService emailService = new EmailService(_credentials);
			string emailBody = System.IO.File.ReadAllText("App_Data/signed.html");

			emailBody = emailBody.Replace("%%%signer_name%%%", envelope.Signers[0].Email);
			emailBody = emailBody.Replace("%%%url%%%", host);

			emailService.Send(new EmailMessage() {
				Body = emailBody,
				Destination = envelope.Sender,
				Subject = "Your document has been signed: " + envelope.Name
			});
		}

	}
}
