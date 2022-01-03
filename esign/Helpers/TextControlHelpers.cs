using esign.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using TXTextControl;
using TXTextControl.ServerVisualisation;

namespace esign.Helpers {
	public class TextControlHelpers : IDisposable {

		LoadSettings ls = new LoadSettings() { ApplicationFieldFormat = ApplicationFieldFormat.MSWord };
		TextViewGenerator tx;

		public TextControlHelpers(string document) {
			tx = new TextViewGenerator();
			tx.Create();
			tx.Load(ls, Convert.FromBase64String(document));
		}

		public TextControlHelpers() {
			tx = new TextViewGenerator();
			tx.Create();
		}

		public void Dispose() {
			tx.Dispose();
		}

		public MemoryStream GetInternalFormat() {
			byte[] data = null;
			tx.Save(out data, BinaryStreamType.InternalUnicodeFormat);

			return new MemoryStream(data);
		}

		public bool HasTrackedChanges() {
			var hasChanges = false;

			if (tx.TrackedChanges.Count > 0)
				hasChanges = true;

			return hasChanges;
		}

		public MemoryStream MergeJson(string Json) {
			using (TXTextControl.DocumentServer.MailMerge mm = new TXTextControl.DocumentServer.MailMerge()) {
				mm.TextComponent = tx;

				mm.MergeJsonData(Json);

				byte[] data = null;
				tx.Save(out data, BinaryStreamType.InternalUnicodeFormat);

				return new MemoryStream(data);
			}
		}

		public MemoryStream GenerateAgreement(List<string> Sections) {
			using (TXTextControl.DocumentServer.MailMerge mm = new TXTextControl.DocumentServer.MailMerge()) {
				mm.TextComponent = tx;

				List<string> sectionNames = new List<string>();

				foreach(SubTextPart sectionName in tx.SubTextParts) {
					sectionNames.Add(sectionName.Name);
				}

				foreach (string name in sectionNames) {

					if (Sections.Contains(name) == false) {
						SubTextPart subTextPart = tx.SubTextParts.GetItem(name);
						tx.Select(subTextPart.Start - 1, subTextPart.Length + 1);
						tx.Selection.Text = "";
					}
				}

				byte[] data = null;
				tx.Save(out data, BinaryStreamType.InternalUnicodeFormat);

				return new MemoryStream(data);
			}
		}

		public byte[] GetThumbnail() {

			Bitmap bmp = tx.GetPages()[1].GetImage(100, Page.PageContent.All);

			using (var ms = new MemoryStream()) {
				using (var bitmap = tx.GetPages()[1].GetImage(100, Page.PageContent.All)) {
					bitmap.Save(ms, System.Drawing.Imaging.ImageFormat.Jpeg);
					return ms.GetBuffer();
				}
			}
		}

		public List<FieldModel> GetMergeFields() {

			List<FieldModel> appFields = new List<FieldModel>();

			foreach(ApplicationField field in tx.ApplicationFields) {

				if (field.TypeName != "MERGEFIELD")
					continue;
				
				appFields.Add(new FieldModel() { 
					Name = field.Parameters[0],
					Value = field.Text
				});
			}

			return appFields;
		}

		public List<SectionModel> GetSubTextParts() {

			List<SectionModel> sections = new List<SectionModel>();

			foreach (SubTextPart textPart in tx.SubTextParts) {

				sections.Add(new SectionModel() {
					Name = textPart.Name,
					Active = true
				});
			}

			return sections;
		}

		public byte[] ConditionToId(bool reverse = false) {
			((TextViewGenerator)tx).IsFormFieldValidationEnabled = true;
			
			if (reverse == true)
				tx.FormFields.ConditionalInstructions.Clear();

			foreach (FormField field in tx.FormFields) { 

				if (reverse == false) { 
					foreach (ConditionalInstruction instruction in ((TextViewGenerator)tx).FormFields.ConditionalInstructions.GetItems(field)) {
						if (instruction.Conditions[0].ComparisonOperator == Condition.ComparisonOperators.Is &&
							instruction.Conditions[0].ComparisonValue == null &&
							instruction.Conditions[0].ComparisonValueType == Condition.ComparisonValueTypes.NoValue) {

							if (instruction.Instructions[0].InstructionType == Instruction.InstructionTypes.IsValueValid &&
								(bool)instruction.Instructions[0].InstructionValue == false) {
								field.ID = 1;
							}
						}
						else
							field.ID = 0;
					}
				}
				else {

					if (field.ID == 1) {

						if (field is TextFormField) {
							ConditionalInstruction instruction = new ConditionalInstruction(Guid.NewGuid().ToString(),
								new Condition[] { new Condition((TextFormField)field, Condition.ComparisonOperators.Is, null) },
								new Instruction[] { new Instruction((TextFormField)field, Instruction.InstructionTypes.IsValueValid, false, true) });

							tx.FormFields.ConditionalInstructions.Add(instruction);
						}

						if (field is DateFormField) {
							ConditionalInstruction instruction = new ConditionalInstruction(Guid.NewGuid().ToString(),
								new Condition[] { new Condition((DateFormField)field, Condition.ComparisonOperators.Is, null) },
								new Instruction[] { new Instruction((DateFormField)field, Instruction.InstructionTypes.IsValueValid, false) });

							tx.FormFields.ConditionalInstructions.Add(instruction);
						}

					}
				}
			}

			byte[] data;
			tx.Save(out data, BinaryStreamType.InternalUnicodeFormat);
			return data;
		}

		public string GetDocumentAccessId(byte[] document) {
			TXTextControl.LoadSettings ls = new LoadSettings();

			try {
				tx.Load(document, BinaryStreamType.AdobePDF, ls);
			}
			catch { return null; }

			if (ls.EmbeddedFiles == null)
				return null;

			foreach (EmbeddedFile file in ls.EmbeddedFiles) {
				if (file.FileName == "__txesign_documentaccessid")
					return Encoding.UTF8.GetString((byte[])file.Data);
			}

			return null;
		}

		public byte[] PrepareFormFields(Signer signer) {

			DeleteFormFields(tx, signer.Id);

			byte[] data;
			tx.Save(out data, BinaryStreamType.InternalUnicodeFormat);
			return data;
		}

			public List<byte[]> CreatePDF(Envelope envelope, string userId, List<string> signedDocuments) {

			if (signedDocuments != null) {
				using (TXTextControl.ServerTextControl svr = new ServerTextControl()) {

					svr.Create();

					int i = 0;

					foreach (Signer signer in envelope.Signers) {
						svr.Load(Convert.FromBase64String(signedDocuments[i]), BinaryStreamType.InternalUnicodeFormat);

						byte[] frame;

						TextFrame signedFrame = svr.TextFrames.GetItem("txsign_" + signer.Id);
						TextFrame destinationFrame = tx.TextFrames.GetItem("txsign_" + signer.Id);

						signedFrame.Selection.Save(out frame, BinaryStreamType.InternalUnicodeFormat);

						destinationFrame.Selection.Start = 0;
						destinationFrame.Selection.Length = -1;

						destinationFrame.Selection.Load(frame, BinaryStreamType.InternalUnicodeFormat);

						destinationFrame.BackColor = signedFrame.BackColor;
						destinationFrame.BorderWidth = signedFrame.BorderWidth;
						destinationFrame.InternalMargins = signedFrame.InternalMargins;

						foreach (FormField sourceFormField in svr.FormFields) {
							foreach (FormField destinationFormField in tx.FormFields) {
								if (sourceFormField.Name == destinationFormField.Name)
									destinationFormField.Text = sourceFormField.Text;
							}
						}

						i++;
					}

				}
			}

			byte[] octets = System.Text.Encoding.ASCII.GetBytes(envelope.EnvelopeID + ":" + userId);
			var envelope_code = Convert.ToBase64String(octets);

			TXTextControl.SaveSettings settings = new TXTextControl.SaveSettings();
			X509Certificate2 cert = new X509Certificate2("App_Data/textcontrolself.pfx", "123");
			settings.DigitalSignature =
				 new TXTextControl.DigitalSignature(cert, null);

			settings.CreatorApplication = "Text Control eSign";

			settings.EmbeddedFiles = new EmbeddedFile[] {
				new EmbeddedFile("__txesign_documentaccessid", Encoding.UTF8.GetBytes(envelope_code), null)
					};

			byte[] data;

			DeleteFormFields(tx);

			tx.Save(out data,
				 TXTextControl.BinaryStreamType.AdobePDFA, settings);

			byte[] thumbnail = GetThumbnail();

			List<byte[]> returnData = new List<byte[]>();
			returnData.Add(data);
			returnData.Add(thumbnail);

			return returnData;
		}

		private void DeleteFormFields(ServerTextControl tx, string signerId = null) {

			if (tx.FormFields.Count == 0)
				return;

			bool bRemovedField = false;

			foreach (FormField field in tx.FormFields) {

				if (signerId != null) {
					var fieldSignerId = field.Name.Split(":")[0];

					if (fieldSignerId == signerId)
						continue;
				}

				tx.Selection.Start = field.Start;

				var text = field.Text;

				tx.FormFields.Remove(field);
				tx.Selection.Text = text;

				bRemovedField = true;

				break;
			}

			if(bRemovedField == true)
				DeleteFormFields(tx, signerId);
		}

		public bool ContainsSignatureBox(List<Signer> signers) {

			int count = 0;

			foreach (Signer signer in signers) { 

				foreach (IFormattedText textPart in tx.TextParts) {
					
					foreach (FrameBase frame in textPart.Frames) {
						if (frame is TXTextControl.TextFrame && frame.Name == "txsign_" + signer.Id) {
							count++; continue;
						}
					}

				}

			}

			return (count == signers.Count) ? true : false;
		}

	}


}
