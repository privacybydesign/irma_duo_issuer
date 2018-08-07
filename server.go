package main

// This file provides the main API for PDF verification and issuance. It also
// serves a few static files from a directory (HTML/CSS/JS).

import (
	"io/ioutil"
	"log"
	"net/http"
	"sort"

	"github.com/privacybydesign/irmago"
)

func sendErrorResponse(w http.ResponseWriter, httpCode int, errorCode string) {
	w.WriteHeader(httpCode)
	w.Write([]byte("error:" + errorCode))
}

func getAttribute(disjunction *irma.AttributeDisjunction, identifiers []irma.AttributeTypeIdentifier) *string {
	for _, identifier := range identifiers {
		if value := disjunction.Values[identifier]; value != nil {
			return value
		}
	}
	return nil
}

func apiRequestAttrs(w http.ResponseWriter, r *http.Request) {
	disjunction := irma.AttributeDisjunctionList{
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
	request := &irma.DisclosureRequest{
		Content: disjunction,
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
	if r.Method != "POST" {
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
	disclosedAttributes := &irma.AttributeDisjunction{}
	err = disclosedAttributes.ParseJwt(attributesJwt, pk, 0, "disclosure_result")
	if err != nil {
		log.Println("cannot parse attribute:", err)
		sendErrorResponse(w, 400, "attributes")
		return
	}
	disclosedInitials := getAttribute(disclosedAttributes, config.InitialsAttributes)
	disclosedFamilyname := getAttribute(disclosedAttributes, config.FamilyNameAttributes)
	disclosedDateOfBirth := getAttribute(disclosedAttributes, config.DateOfBirthAttributes)
	if disclosedInitials == nil || disclosedFamilyname == nil || disclosedDateOfBirth == nil {
		log.Println("disjunction doesn't have the required attributes")
		sendErrorResponse(w, 400, "attributes")
		return
	}

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

	var disjunction irma.AttributeDisjunctionList
	for _, attributes := range attributeSets {
		// Pretty-print attributes in the way they're extracted.
		var keys []string
		for key := range attributes {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		attrs := make([]irma.AttributeTypeIdentifier, 0, len(attributes))
		vals := make(map[irma.AttributeTypeIdentifier]*string, len(attributes))
		for _, key := range keys {
			id := irma.NewAttributeTypeIdentifier("pbdf.pbdf.duo." + key)
			attrs = append(attrs, id)
			value := attributes[key]
			vals[id] = &value
		}
		disjunction = append(disjunction, &irma.AttributeDisjunction{
			Attributes: attrs,
			Values:     vals,
		})
	}

	// TODO: cache, or load on startup
	sk, err := readPrivateKey(configDir + "/sk.pem")
	if err != nil {
		log.Println("cannot open private key:", err)
		sendErrorResponse(w, 500, "signing")
		return
	}

	jwt := irma.NewSignatureRequestorJwt("Privacy by Design Foundation", &irma.SignatureRequest{
		Message: "diploma attributes from PDF",
		DisclosureRequest: irma.DisclosureRequest{
			Content: disjunction,
		},
	})
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
