package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"sort"

	"github.com/privacybydesign/irmago"
)

func sendErrorResponse(w http.ResponseWriter, code string) {
	w.Write([]byte("error:" + code))
}

func apiRequestAttrs(w http.ResponseWriter, r *http.Request) {
	disjunction := irma.AttributeDisjunctionList{
		{
			Label: "Family name",
			Attributes: []irma.AttributeTypeIdentifier{
				irma.NewAttributeTypeIdentifier("pbdf.pbdf.idin.familyname"),
			},
		},
		{
			Label: "Date of birth",
			Attributes: []irma.AttributeTypeIdentifier{
				irma.NewAttributeTypeIdentifier("pbdf.pbdf.idin.dateofbirth"),
			},
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
		sendErrorResponse(w, "signing")
		return
	}

	text, err := jwt.Sign("duo", sk)
	if err != nil {
		log.Println("cannot create disclosure JWT:", err)
		sendErrorResponse(w, "signing")
		return
	}
	w.Write([]byte(text))
}

func apiIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendErrorResponse(w, "invalid-method")
		return
	}
	// Accept files of up to 1MB. The sample PDFs I've used are all 520-550kB so
	// this should be enough.
	err := r.ParseMultipartForm(1024 * 1024) // 1MB
	if err != nil {
		sendErrorResponse(w, "file-too-big")
		return
	}
	file, _, err := r.FormFile("pdf")
	if err != nil {
		sendErrorResponse(w, "no-pdf-file")
		return
	}
	defer file.Close()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		sendErrorResponse(w, "readfile")
		return
	}

	attributeSets, err := verifyAndExtract(data)
	if err != nil {
		log.Println("failed to extract attributes from PDF:", err)
		sendErrorResponse(w, "extract")
		return
	}

	// TODO: verify name

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
		sendErrorResponse(w, "signing")
		return
	}

	jwt := irma.NewSignatureRequestorJwt("Privacy by Design Foundation", &irma.SignatureRequest{
		Message: "diploma attributes from PDF",
		DisclosureRequest: irma.DisclosureRequest{
			Content: disjunction,
		},
	})
	text, err := jwt.Sign("duo", sk)

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
