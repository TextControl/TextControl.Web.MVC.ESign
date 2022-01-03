var TextControl = (function (tx) {

    var currentEnvelope;
    var currentContract;

    tx.esign = {

        currentContract: function () {
            return currentContract;
        },

        deleteSection: function () {
            TXTextControl.subTextParts.getItem(section => {
                TXTextControl.subTextParts.remove(section, true, false);
                TextControl.esign.updateSectionList();
            })
        },

        updateSectionName: function () {
            TXTextControl.selection.getStart(function (curSelStart) {

                TXTextControl.paragraphs.getItemAtTextPosition(curSelStart, function (par) {
                    par.getText(text => {

                        var title = text.trim();

                        if (title.length > 30)
                            title = title.substr(0, 30) + "[...]";

                        document.getElementById("section-name").value = title;
                    })
                })

            })
        },

        updateSectionList: function () {

            $("#availableSections").empty();

            TXTextControl.subTextParts.forEach(section => {

                section.setHighlightMode(TXTextControl.HighlightMode.Activated, function () {
                    section.getName(name => {

                        section.getData(id => {
                            $("#availableSections").append('<a onclick="TextControl.esign.activateSection(\'' + id + '\')" class="list-group-item list-group-item-action toolbox-item"><span class="material-icons left">wysiwyg</span><p class="sidebar-small">' + name + '</p></a>');
                        })
                    })
                })

            })
        },

        activateSection: function (id) {
            TXTextControl.subTextParts.forEach(part => {
                part.getData(data => {
                    if (data === id) {
                        part.getStart(start => {
                            part.scrollTo();
                            TXTextControl.selection.setStart(start - 1, function () { TXTextControl.focus(); });
                            
                            return;
                        })
                    }
                })
            })
        },

        addSection: function () {

            TXTextControl.selection.getStart(function (curSelStart) {
                TXTextControl.selection.getLength(function (curSelLength) {

                    var range = {
                        start: curSelStart + 1,
                        length: curSelLength,
                    };

                    var fullRange = {
                        start: 0,
                        length: 0,
                    };

                    var name = document.getElementById("section-name").value;

                    TXTextControl.paragraphs.getItemAtTextPosition(range.start, function (par) {
                        par.getStart(start => {
                            fullRange.start = start;

                            TXTextControl.paragraphs.getItemAtTextPosition(range.start + range.length, function (secondPar) {
                                secondPar.getStart(startSecond => {

                                    secondPar.getLength(length => {
                                        fullRange.length = (startSecond + length) - fullRange.start;

                                        TXTextControl.subTextParts.add(name, 0, fullRange.start, fullRange.length - 1, part => {

                                            if (part.addResult === 1) {
                                                part.subTextPart.setHighlightColor("rgba(0,255,0,.5)", function () {
                                                    part.subTextPart.setData(uuidv4(), function () {
                                                        TXTextControl.focus();
                                                        TextControl.esign.updateSectionList();
                                                    });
                                                });
                                            }
                                            else {
                                                TextControl.esign.showToast("Section cannot be inserted at this location.")
                                            }

                                            
                                        });
                                        
                                    })

                                })
                            });
                        })
                    });

                   
                });
            });
            
        },

        addFile: function (files) {
            var file = files[0];

            var data = new FormData();
            data.append(file.name, file);

            uploadDocument(data);
        },

        addContract: function (files) {
            var file = files[0];

            var data = new FormData();
            data.append(file.name, file);

            uploadContract(data);
        },

        addTemplate: function (files) {
            var file = files[0];

            var data = new FormData();
            data.append(file.name, file);

            uploadTemplate(data);
        },

        addAgreement: function (files) {
            var file = files[0];

            var data = new FormData();
            data.append(file.name, file);

            uploadAgreement(data);
        },

        getDocument: function (documentid, typeString) {
            $.ajax({
                type: "GET",
                url: "/" + typeString + "/document/" + documentid,
                success: function (data) {
                    TXTextControl.loadDocument(32, data, function () {
                        TextControl.esign.checkTextFrames();
                    });
                },
                error: function () {
                    console.log("Error");
                },
                beforeSend: function () {
                    $(".waitstate").addClass("visible");
                },
                complete: function () {
                    $(".waitstate").removeClass("visible");
                }
            });
        },

        getContract: function (documentid) {
            $.ajax({
                type: "GET",
                url: "/collaboration/document/" + documentid,
                success: function (data) {
                    TXTextControl.loadDocument(32, data);
                },
                error: function () {
                    console.log("Error");
                },
                beforeSend: function () {
                    $(".waitstate").addClass("visible");
                },
                complete: function () {
                    $(".waitstate").removeClass("visible");
                }
            });
        },

        loadEditor: function (documentid) {
            if (typeof TXTextControl !== 'undefined')
                TXTextControl.removeFromDom();

            // load the partial view
            $("#editor").load("/Partial/Edit/" + documentid);
            $("#editor").addClass("action");
            $("#main").addClass("inactive");
            $(".navbar").removeClass("fixed-top");
        },

        loadTemplateEditor: function (documentid) {
            if (typeof TXTextControl !== 'undefined')
                TXTextControl.removeFromDom();

            // load the partial view
            $("#editor").load("/Partial/EditTemplate/" + documentid);
            $("#editor").addClass("action");
            $("#main").addClass("inactive");
            $(".navbar").removeClass("fixed-top");
        },

        loadAgreementEditor: function (documentid) {
            if (typeof TXTextControl !== 'undefined')
                TXTextControl.removeFromDom();

            // load the partial view
            $("#editor").load("/Partial/EditAgreement/" + documentid);
            $("#editor").addClass("action");
            $("#main").addClass("inactive");
            $(".navbar").removeClass("fixed-top");
        },

        insertMergeField: function () {
            var mergeField = new TXTextControl.MergeField;
            mergeField.name = "mergefield";
            mergeField.text = "«mergefield»";
            TXTextControl.addMergeField(mergeField);
        },

        insertDateField: function () {
            var dateField = new TXTextControl.DateField;
            dateField.name = "date";
            TXTextControl.addMergeField(dateField);
        },

        insertTextFrame: function (id, name) {
            TXTextControl.selection.getStart(function (start) {
                TXTextControl.textFrames.addAnchored(
                    { width: 2000, height: 1000 },
                    TXTextControl.HorizontalAlignment.Left,
                    start, // TextPosition
                    TXTextControl.TextFrameInsertionMode.AboveTheText,

                    (addedTextFrame) => {
                        addedTextFrame.selection.setText("Signature box: " + name);
                        addedTextFrame.setBackColor("#ffc107");
                        addedTextFrame.setName("txsign_" + id);
                        addedTextFrame.setBorderWidth(50);
                        addedTextFrame.setTransparency(.2);

                        TextControl.esign.checkTextFrames();
                    }
                );
            });
        },

        checkTextFrames: function () {

            $(".toolbox-item-small").removeClass("checked");

            TXTextControl.textFrames.forEach(function (frame) {
                frame.getName(function (name) {
                    $("#" + name).addClass("checked");
                });
            });

        },

        insertTextFormField: function () {
            TXTextControl.formFields.getCanAdd(canAdd => {
                if (canAdd) {

                    var formOwner = $("#formOwner").val();

                    // Add form field
                    TXTextControl.formFields.addTextFormField(3000, ff => {
                        ff.setName(formOwner + ":" + uuidv4());
                    });

                } else {
                    TextControl.esign.showToast("Form field cannot be inserted at this location.");
                }
            });
        },

        insertDropDownFormField: function () {
            TXTextControl.formFields.getCanAdd(canAdd => {
                if (canAdd) {

                    var formOwner = $("#formOwner").val();

                    // Add form field
                    TXTextControl.formFields.addSelectionFormField(3000, ff => {
                        var items = ["Entry1", "Entry2"];

                        ff.setEditable(false);
                        ff.setName(formOwner + ":" + uuidv4());
                        ff.setItems(items);
                        ff.setSelectedIndex(1);
                    });
                } else {
                    TextControl.esign.showToast("Form field cannot be inserted at this location.");
                }
            });
        },

        insertCheckbox: function () {
            TXTextControl.formFields.getCanAdd(canAdd => {
                if (canAdd) {

                    var formOwner = $("#formOwner").val();

                    // Add form field
                    TXTextControl.formFields.addCheckFormField(true, ff => {
                        ff.setName(formOwner + ":" + uuidv4());
                    });

                } else {
                    TextControl.esign.showToast("Form field cannot be inserted at this location.");
                }
            });
        },

        insertDatePicker: function () {
            TXTextControl.formFields.getCanAdd(canAdd => {
                if (canAdd) {

                    var formOwner = $("#formOwner").val();

                    // Add form field
                    TXTextControl.formFields.addDateFormField(1000, ff => {
                        ff.setName(formOwner + ":" + uuidv4());
                    });
                } else {
                    TextControl.esign.showToast("Form field cannot be inserted at this location.");
                }
            });
        },

        copyLink: function (link) {

            var copyText = document.getElementById(link);

            copyText.select();
            copyText.setSelectionRange(0, 99999);

            document.execCommand("copy");

            TextControl.esign.showToast("Value copied to clipboard!");
        },

        saveEditor: function (documentContent, envelopeId) {
            var signModel = { "document": documentContent };

            $.ajax({
                type: "POST",
                url: "/envelope/saveDocument/" + envelopeId,
                contentType: "application/json",
                data: JSON.stringify(signModel),
                success: function (status) {
                    TextControl.esign.showToast("Document successfully saved!");
                    $("#editor").removeClass("action");
                    $("#main").removeClass("inactive");
                    $(".navbar").addClass("fixed-top");
                    $('#collapseSignature').load('/partial/SignatureBox/' + envelopeId);
                },
                error: function () {
                    TextControl.esign.showToast("Something went wrong!");
                },
                beforeSend: function () {
                    TextControl.esign.showToast("Saving...");
                },
                complete: function () {
                    
                }
            });
        },

        saveTemplate: function (documentContent, envelopeId) {
            var signModel = { "document": documentContent };

            $.ajax({
                type: "POST",
                url: "/template/saveDocument/" + envelopeId,
                contentType: "application/json",
                data: JSON.stringify(signModel),
                success: function (status) {
                    TextControl.esign.showToast("Document successfully saved!");
                    $("#editor").removeClass("action");
                    $("#main").removeClass("inactive");
                    $(".navbar").addClass("fixed-top");

                    tx.esign.getApplicationFields(envelopeId);
                    
                },
                error: function () {
                    TextControl.esign.showToast("Something went wrong!");
                },
                beforeSend: function () {
                    TextControl.esign.showToast("Saving...");
                },
                complete: function () {

                }
            });
        },

        saveAgreement: function (documentContent, envelopeId) {
            var signModel = { "document": documentContent };

            $.ajax({
                type: "POST",
                url: "/agreement/saveDocument/" + envelopeId,
                contentType: "application/json",
                data: JSON.stringify(signModel),
                success: function (status) {
                    TextControl.esign.showToast("Document successfully saved!");
                    $("#editor").removeClass("action");
                    $("#main").removeClass("inactive");
                    $(".navbar").addClass("fixed-top");
                },
                error: function () {
                    TextControl.esign.showToast("Something went wrong!");
                },
                beforeSend: function () {
                    TextControl.esign.showToast("Saving...");
                },
                complete: function () {

                }
            });
        },

        saveContract: function (documentContent, contractId, owner) {
            var collaborationModel = { "document": documentContent };

            $.ajax({
                type: "POST",
                url: "/collaboration/saveDocument/" + contractId + "?owner=" + owner,
                contentType: "application/json",
                data: JSON.stringify(collaborationModel),
                success: function (status) {
                    window.location.href = status;
                },
                error: function () {
                    TextControl.esign.showToast("Something went wrong!");
                },
                beforeSend: function () {
                    TextControl.esign.showToast("Saving...");
                },
                complete: function () {
                    
                }
            });
        },

        submitEnvelope: function (envelopeId) {
            $.ajax({
                type: "POST",
                url: "/envelope/submit/" + envelopeId,
                contentType: "application/json",
                success: function (status) {
                    TextControl.esign.showToast("Envelope successfully sent!");
                    $("#statusReview").addClass("status-check");
                    $("#submitButtons").hide();
                    $("#readyButton").removeClass("visually-hidden");
                },
                error: function () {
                    console.log("Error");
                },
                beforeSend: function () {
                    $(".waitstate").addClass("visible");
                },
                complete: function () {
                    $(".waitstate").removeClass("visible");
                }
            });
        },

        submitContract: function (contractId) {
            $.ajax({
                type: "POST",
                url: "/contract/submit/" + contractId,
                contentType: "application/json",
                success: function (status) {
                    TextControl.esign.showToast("Envelope successfully sent!");
                    $("#statusReview").addClass("status-check");
                    $("#submitButtons").hide();
                    $("#readyButton").removeClass("visually-hidden");
                },
                error: function () {
                    console.log("Error");
                },
                beforeSend: function () {
                    $(".waitstate").addClass("visible");
                },
                complete: function () {
                    $(".waitstate").removeClass("visible");
                }
            });
        },

        getApplicationFields: function (templateId) {
            $.ajax({
                type: "POST",
                url: "/template/getfields/" + templateId,
                contentType: "application/json",
                success: function (status) {

                    console.log(status);

                    $("#tx-fields").empty();

                    $("#tx-fields").append("<form id='submitfields' method='post' action='/template/instance/" + templateId + "' >");

                    if (status.length === 0) {
                        $("#submitfields").append("<p>No merge fields found.</p>");
                    }
                    else {

                        status.forEach(function (field) {
                            $("#submitfields").append("<div class='mt-2'><label for='" + field.name + "' class='form-label'>" + field.name + "</label><input class='form-control' type='text' placeholder='Complete this field' name='" + field.name + "' id='" + field.name + "' /></div>");
                        });

                    }

                    $("#submitfields").append("<input value='Create Instance' class='mt-5 btn btn-warning' type='submit'>");
                },
                error: function () {
                    console.log("Error");
                },
                beforeSend: function () {
                    $(".waitstate").addClass("visible");
                },
                complete: function () {
                    $(".waitstate").removeClass("visible");
                }
            });
        },

        getAgreementSections: function (templateId) {
            $.ajax({
                type: "POST",
                url: "/agreement/getsections/" + templateId,
                contentType: "application/json",
                success: function (status) {

                    console.log(status);

                    $("#tx-sections").empty();

                    $("#tx-sections").append("<form id='submitsections' method='post' action='/agreement/instance/" + templateId + "' >");

                    if (status.length === 0) {
                        $("#submitsections").append("<p>No sections found.</p>");
                    }
                    else {

                        var sChecked = "";

                        status.forEach(function (field) {

                            if (field.active === true)
                                sChecked = "checked";

                            $("#submitsections").append("<div class='mt-2'><input " + sChecked + " class='form-check-input' value='true' type='checkbox' name='" + field.name + "' id='" + field.name + "' /><label for='" + field.name + "' class='form-check-label mx-2'>" + field.name + "</label></div>");
                        });

                    }

                    $("#submitsections").append("<input value='Create Instance' class='mt-5 btn btn-warning' type='submit'>");
                },
                error: function () {
                    console.log("Error");
                },
                beforeSend: function () {
                    $(".waitstate").addClass("visible");
                },
                complete: function () {
                    $(".waitstate").removeClass("visible");
                }
            });
        },

        submitSignaturebox: function (envelopeId) {
            $("#statusSignature").addClass("status-check");
            $("#statusReview").addClass("status-active");
            TextControl.esign.showToast("Signature box successfully updated!");
            TextControl.esign.nextStep('collapseReview');

            $("#reviewRecipient").empty();

            currentEnvelope.signers.forEach(function (signer) {
                $("#reviewRecipient").append("<li>" + signer.email + "</li>")
            });

        },

        showToast: function (statusText) {
            $("#liveToastMessage").text(statusText);
            var myToast = document.getElementById("liveToast");
            var toast = new bootstrap.Toast(myToast);
            toast.show();
        },

        removeRecipient: function (envelopeId, type, email, name) {
            var url = "/" + type + "/removerecipient/" + envelopeId;

            var data = { "name": name, "email": email };

            $.ajax({
                type: "POST",
                url: url,
                contentType: "application/json",
                data: JSON.stringify(data),
                success: function (envelope) {
                    currentEnvelope = envelope;
                    TextControl.esign.showToast("Recipient successfully removed!");

                    updateRecipients(currentEnvelope.signers, envelopeId, type);

                    $("#recipientAlreadyAdded").addClass("collapse");
                },
                error: function (data) {
                    
                },
            });
        },

        receiveRecipients: function (envelopeId, type) {
            var url = "/" + type + "/receiverecipients/" + envelopeId;

            $.ajax({
                type: "GET",
                url: url,
                contentType: "application/json",
                success: function (envelope) {
                    currentEnvelope = envelope;

                    updateRecipients(currentEnvelope.signers, envelopeId, type);

                    $("#signerName").val("");
                    $("#signerEmail").val("");
                },
                error: function (data) {
                    $("#recipientAlreadyAdded").removeClass("collapse");
                },
            });
        },

        submitRecipient: function (envelopeId, type) {
            var forms = document.querySelectorAll('.needs-validation')

            var url = "/" + type + "/updaterecipient/" + envelopeId;

            Array.prototype.slice.call(forms)
                .forEach(function (form) {

                    form.addEventListener('submit', function (event) {
                        event.preventDefault()
                        event.stopPropagation()
                    }, false)

                    if (!form.checkValidity()) {
                        form.classList.add('was-validated');
                        return;
                    }
                    else {
                        var name = $("#signerName").val();
                        var email = $("#signerEmail").val();

                        var data = { "name": name, "email": email };

                        $.ajax({
                            type: "POST",
                            url: url,
                            contentType: "application/json",
                            data: JSON.stringify(data),
                            success: function (envelope) {
                                currentEnvelope = envelope;
                                TextControl.esign.showToast("Recipient successfully updated!");

                                if (type === "envelope") {
                                    updateRecipients(currentEnvelope.signers, envelopeId, type);

                                    $("#recipientAlreadyAdded").addClass("collapse");

                                    $("#signerName").val("");
                                    $("#signerEmail").val("");
                                }
                                else if (type === "contract") {
                                    $("#statusRecipient").addClass("status-check");
                                    TextControl.esign.nextStep('collapseReview');

                                    $("#reviewRecipient").text(currentEnvelope.signer.email);
                                }
                            },
                            error: function (data) {
                                $("#recipientAlreadyAdded").removeClass("collapse");
                            },
                        });
                    }
                });
        },

        confirmRecipients: function () {
            $("#statusRecipient").addClass("status-check");
            $("#statusSignature").addClass("status-active");
            TextControl.esign.nextStep('collapseSignature');
        },

        dropHandler: function (ev) {
            ev.preventDefault();
            var file;

            if (ev.dataTransfer.items) {

                if (ev.dataTransfer.items[0].kind === 'file') {
                    file = ev.dataTransfer.items[0].getAsFile();
                }
            } else {
                // Use DataTransfer interface to access the file(s)
                file = ev.dataTransfer.files[0];
            }

            var data = new FormData();
            data.append(file.name, file);

            uploadDocument(data);
        },

        dragOverHandler: function (ev) {
            ev.preventDefault();
        },

        nextStep: function (collapse) {

            $("#processSteps .collapse").each(function () {
                var myCollapse = document.getElementById(this.id)
                var bsCollapse = new bootstrap.Collapse(myCollapse, {
                    toggle: false
                });

                bsCollapse.hide();
            });

            var myCollapse = document.getElementById(collapse);
            var bsCollapse = new bootstrap.Collapse(myCollapse, {
                toggle: false
            })

            bsCollapse.show();

            $(".status-check").parent().addClass("status-border-checked");
        },

        createNew: function (demo) {
            $.ajax({
                type: "POST",
                url: "/envelope/createnew?demo=" + demo,
                contentType: false,
                processData: false,
                success: function (message) {
                    window.location.href = "/envelope/create/" + message;
                },
                error: function () {
                    console.log("Error");
                },
                beforeSend: function () {
                    $(".waitstate").addClass("visible");
                },
                complete: function () {
                    $(".waitstate").removeClass("visible");
                }
            });
        },

        createNewContract: function () {
            $.ajax({
                type: "POST",
                url: "/contract/createnew/",
                contentType: false,
                processData: false,
                success: function (message) {
                    displayContractPreview(message);
                },
                error: function () {
                    console.log("Error");
                },
                beforeSend: function () {
                    $(".waitstate").addClass("visible");
                },
                complete: function () {
                    $(".waitstate").removeClass("visible");
                }
            });
        },

        createNewTemplate: function () {
            $.ajax({
                type: "POST",
                url: "/template/createnew/",
                contentType: false,
                processData: false,
                success: function (message) {
                    displayTemplatePreview(message);
                },
                error: function () {
                    console.log("Error");
                },
                beforeSend: function () {
                    $(".waitstate").addClass("visible");
                },
                complete: function () {
                    $(".waitstate").removeClass("visible");
                }
            });

        },

        createNewAgreement: function (sample) {

            var requestUrl = "";

            if (sample === true)
                requestUrl = "/agreement/createnew?sample=true";
            else
                requestUrl = "/agreement/createnew?sample=false";

            $.ajax({
                type: "POST",
                url: requestUrl,
                contentType: false,
                processData: false,
                success: function (message) {
                    displayAgreementPreview(message);
                },
                error: function () {
                    console.log("Error");
                },
                beforeSend: function () {
                    $(".waitstate").addClass("visible");
                },
                complete: function () {
                    $(".waitstate").removeClass("visible");
                }
            });
        }

    }

    function uuidv4() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    function displayContractPreview(object) {

        currentContract = object;

        $("#statusDocumentThumbnail").attr("src", "data:image/jpeg;base64, " + object.thumbnail);
        $("#statusDocumentInfo").text(object.contract.name);
        $("#contractUploadBox").hide();
        $("#contractPreviewBox").show();

        $("#statusDocument").addClass("status-check");
        $("#statusRecipient").addClass("status-active");
        TextControl.esign.showToast("Document successfully uploaded!");
        TextControl.esign.nextStep("collapseRecipient");
    }

    function displayTemplatePreview(object) {
        $("#statusDocumentThumbnail").attr("src", "data:image/jpeg;base64, " + object.thumbnail);
        $("#statusDocumentInfo").text(object.template.name);
        $("#contractUploadBox").hide();
        $("#contractPreviewBox").show();

        $("#statusDocument").addClass("status-check");
        TextControl.esign.showToast("Template successfully created!");
    }

    function displayAgreementPreview(object) {
        $("#statusDocumentThumbnail").attr("src", "data:image/jpeg;base64, " + object.thumbnail);
        $("#statusDocumentInfo").text(object.agreement.name);
        $("#contractUploadBox").hide();
        $("#contractPreviewBox").show();

        $("#statusDocument").addClass("status-check");
        TextControl.esign.showToast("Agreement successfully created!");
    }

    function updateRecipients(recipients, envelopeId, type) {
        $("#listRecipients").empty();

        recipients.forEach(function (signer) {
            $("#listRecipients").append("<div class=\"list-group-item list-group-item-action\" aria-current=\"true\"><div class=\"d-flex w-100 justify-content-between\" ><h5 class=\"mb-1\">" + signer.name + "</h5><a class=\"btn btn-sm btn-outline-danger\" onclick=\"TextControl.esign.removeRecipient('" + envelopeId + "','" + type + "','" + signer.email + "','" + signer.name + "');\">Remove</a></div ><p class=\"mb-1\">" + signer.email + "</p></div >");
        });

        if (recipients.length != 0) {
            $("#btnConfirmRecipients").removeClass("disabled");
        }
        else {
            $("#btnConfirmRecipients").addClass("disabled");
        }
    }

    function uploadDocument(data) {
        $.ajax({
            type: "POST",
            url: "/envelope/new",
            contentType: false,
            processData: false,
            data: data,
            success: function (message) {
                window.location.href = "/envelope/create/" + message;
            },
            error: function () {
                console.log("Error");
            },
            beforeSend: function () {
                $(".waitstate").addClass("visible");
            },
            complete: function () {
                $(".waitstate").removeClass("visible");
            }
        });
    }

    function uploadContract(data) {
        $.ajax({
            type: "POST",
            url: "/contract/new",
            contentType: false,
            processData: false,
            data: data,
            success: function (message) {
                displayContractPreview(message);
            },
            error: function () {
                console.log("Error");
            },
            beforeSend: function () {
                $(".waitstate").addClass("visible");
            },
            complete: function () {
                $(".waitstate").removeClass("visible");
            }
        });
    }

    function uploadTemplate(data) {
        $.ajax({
            type: "POST",
            url: "/template/new",
            contentType: false,
            processData: false,
            data: data,
            success: function (message) {
                displayTemplatePreview(message);
            },
            error: function () {
                console.log("Error");
            },
            beforeSend: function () {
                $(".waitstate").addClass("visible");
            },
            complete: function () {
                $(".waitstate").removeClass("visible");
            }
        });
    }

    function uploadAgreement(data) {
        $.ajax({
            type: "POST",
            url: "/agreement/new",
            contentType: false,
            processData: false,
            data: data,
            success: function (message) {
                displayAgreementPreview(message);
            },
            error: function () {
                console.log("Error");
            },
            beforeSend: function () {
                $(".waitstate").addClass("visible");
            },
            complete: function () {
                $(".waitstate").removeClass("visible");
            }
        });
    }

    $('#uploadbox').click(function () {
        $('#files').click();
    });

    $('.prevent').click(function (e) {
        e.stopPropagation();
    });

    $("#processForm").submit(function (event) {
        event.preventDefault()
        event.stopPropagation()
    });

    return tx;

}(TextControl || {}));