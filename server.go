package main

// This file provides the main API for PDF verification and issuance. It also
// serves a few static files from a directory (HTML/CSS/JS).

import (
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/privacybydesign/irmago"
)

func sendErrorResponse(w http.ResponseWriter, httpCode int, errorCode string) {
	w.WriteHeader(httpCode)
	w.Write([]byte("error:" + errorCode))
}

func getAttribute(attributes map[irma.AttributeTypeIdentifier]irma.TranslatedString, identifiers []irma.AttributeTypeIdentifier) *string {
	for _, identifier := range identifiers {
		if value, ok := attributes[identifier]; ok {
			// Language should not matter here.
			// If it matters, the Dutch format should be picked anyway as the
			// diplomas themselves are in Dutch.
			s := value["nl"]
			return &s
		}
	}
	return nil
}

func requiredAttributes(initials, familyname, dob *string) irma.AttributeDisjunctionList {
	disjunctions := irma.AttributeDisjunctionList{
		{
			Label:      "Initials",
			Attributes: config.InitialsAttributes,
		},
		{
			Label:      "Family name",
			Attributes: config.FamilyNameAttributes,
		},
		{
			Label:      "Date of birth",
			Attributes: config.DateOfBirthAttributes,
		},
	}
	if initials != nil {
		requireValue(disjunctions[0], initials)
	}
	if familyname != nil {
		requireValue(disjunctions[1], familyname)
	}
	if dob != nil {
		requireValue(disjunctions[2], dob)
	}
	return disjunctions
}

func requireValue(disjunction *irma.AttributeDisjunction, value *string) {
	disjunction.Values = map[irma.AttributeTypeIdentifier]*string{}
	for _, attr := range disjunction.Attributes {
		disjunction.Values[attr] = value
	}
}

func apiRequestAttrs(w http.ResponseWriter, r *http.Request) {
	if config.CORSDomain != "" {
		w.Header().Set("Access-Control-Allow-Origin", config.CORSDomain)
	}

	request := &irma.DisclosureRequest{
		Content: requiredAttributes(nil, nil, nil),
	}
	jwt := irma.NewServiceProviderJwt("Privacy by Design Foundation", request)

	// TODO: cache, or load on startup
	sk, err := readPrivateKey(configDir + "/sk.pem")
	if err != nil {
		log.Println("cannot open private key:", err)
		sendErrorResponse(w, 500, "signing")
		return
	}

	text, err := jwt.Sign("duo", sk)
	if err != nil {
		log.Println("cannot create disclosure JWT:", err)
		sendErrorResponse(w, 500, "signing")
		return
	}
	w.Write([]byte(text))
}

func apiIssue(w http.ResponseWriter, r *http.Request) {
	if config.CORSDomain != "" {
		w.Header().Set("Access-Control-Allow-Origin", config.CORSDomain)
	}

	if r.Method != http.MethodPost {
		sendErrorResponse(w, 405, "invalid-method")
		return
	}

	// TODO: cache, or load on startup
	pk, err := readPublicKey(configDir + "/apiserver-pk.pem")
	if err != nil {
		log.Println("cannot open public key of API server:", err)
		sendErrorResponse(w, 500, "attributes")
		return
	}

	attributesJwt := r.FormValue("attributes")
	disclosedAttributes, err := irma.ParseDisclosureJwt(attributesJwt, pk)
	if err != nil {
		if _, ok := err.(irma.ExpiredError); ok {
			sendErrorResponse(w, 400, "attributes-expired")
		} else {
			log.Println("cannot parse attribute:", err)
			sendErrorResponse(w, 400, "attributes")
		}
		return
	}
	disclosedInitials := getAttribute(disclosedAttributes, config.InitialsAttributes)
	disclosedFamilyname := getAttribute(disclosedAttributes, config.FamilyNameAttributes)
	disclosedDateOfBirth := getAttribute(disclosedAttributes, config.DateOfBirthAttributes)

	// Accept files of up to 1MB. The sample PDFs I've used are all 520-550kB so
	// this should be enough.
	err = r.ParseMultipartForm(1024 * 1024) // 1MB
	if err != nil {
		sendErrorResponse(w, 413, "file-too-big")
		return
	}
	file, _, err := r.FormFile("pdf")
	if err != nil {
		sendErrorResponse(w, 400, "no-pdf-file")
		return
	}
	defer file.Close()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		sendErrorResponse(w, 500, "readfile")
		return
	}

	attributeSets, err := verifyAndExtract(data)
	if err != nil {
		log.Println("failed to extract attributes from PDF:", err)
		sendErrorResponse(w, 400, "extract")
		return
	}

	for _, attributes := range attributeSets {
		familyname := attributes["familyname"]
		if attributes["prefix"] != "" {
			familyname = attributes["prefix"] + " " + familyname
		}
		if len(attributes["firstname"]) == 0 || len(*disclosedInitials) == 0 {
			// This is very unlikely.
			sendErrorResponse(w, 400, "no-initials")
			return
		}
		if familyname != *disclosedFamilyname || attributes["firstname"][0] != (*disclosedInitials)[0] {
			sendErrorResponse(w, 400, "name-match")
			return
		}
		if attributes["dateofbirth"] != *disclosedDateOfBirth {
			sendErrorResponse(w, 400, "dateofbirth-match")
			return
		}
	}

	validity := irma.Timestamp(irma.FloorToEpochBoundary(time.Now().AddDate(1, 0, 0)))
	credid := irma.NewCredentialTypeIdentifier(config.DUOCrendentialID)
	var credentials []*irma.CredentialRequest
	for _, attributes := range attributeSets {
		credential := &irma.CredentialRequest{
			Validity:         &validity,
			CredentialTypeID: &credid,
			Attributes:       attributes,
		}
		credentials = append(credentials, credential)
	}

	// TODO: cache, or load on startup
	sk, err := readPrivateKey(configDir + "/sk.pem")
	if err != nil {
		log.Println("cannot open private key:", err)
		sendErrorResponse(w, 500, "signing")
		return
	}

	req := &irma.IssuanceRequest{
		Credentials: credentials,
		Disclose:    requiredAttributes(disclosedInitials, disclosedFamilyname, disclosedDateOfBirth),
	}
	jwt := irma.NewIdentityProviderJwt("Privacy by Design Foundation", req)
	text, err := jwt.Sign("duo", sk)
	if err != nil {
		log.Println("cannot sign signature request:", err)
		sendErrorResponse(w, 500, "signing")
		return
	}

	w.Write([]byte(text))
}

func cmdServe(addr string) {
	static := http.FileServer(http.Dir(serverStaticDir))
	http.Handle("/", static)
	http.HandleFunc("/api/request-attrs", apiRequestAttrs)
	http.HandleFunc("/api/issue", apiIssue)
	log.Println("serving from", addr)
	http.ListenAndServe(addr, nil)
}
