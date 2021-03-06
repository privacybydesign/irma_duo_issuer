package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/anaskhan96/soup"
	"github.com/mastahyeti/cms"
	"golang.org/x/net/html"
	"rsc.io/pdf"
)

// This file contains code that reads a given PDF diploma file, verifies it, and
// extracts all of its attributes.
// Additionally, it contains a small command-line interface at the bottom (see
// main.go).

type ExtractError struct {
	Op  string
	Err error
}

func (e ExtractError) Error() string {
	if e.Err == nil {
		return e.Op
	}
	return e.Op + ": " + e.Err.Error()
}

// Utility function to dump the structure of a PDF document. Very useful for
// debugging.
func printTree(v pdf.Value, indent int) {
	// Avoid too much recursion.
	if indent > 7 {
		fmt.Println("<max depth exceeded>")
		return
	}

	switch v.Kind() {
	case pdf.Dict:
		fmt.Println()
		for _, key := range v.Keys() {
			for i := 0; i < indent; i++ {
				fmt.Printf("  ")
			}
			fmt.Printf("%s: ", key)
			printTree(v.Key(key), indent+1)
		}
	case pdf.Array:
		fmt.Println()
		for i := 0; i < v.Len(); i++ {
			for i := 0; i < indent; i++ {
				fmt.Printf("  ")
			}
			fmt.Printf("- ")
			printTree(v.Index(i), indent+1)
		}
	case pdf.Integer:
		fmt.Println(v.Int64())
	case pdf.String:
		fmt.Printf("%#v\n", v.Text())
	case pdf.Name:
		fmt.Println(v.Name())
	default:
		fmt.Println("??")
	}
}

// Verify the signature contained in a PDF and return the verified PDF as a byte
// slice.
//
// This function follows the signed PDF specification that you can read here:
// https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSig/Acrobat_DigitalSignatures_in_PDF.pdf
func verifyPDF(inputPDF []byte, pool *x509.CertPool) ([]byte, error) {
	// Open the PDF file.
	r := bytes.NewReader(inputPDF)
	doc, err := pdf.NewReader(r, int64(len(inputPDF)))
	if err != nil {
		return nil, err
	}
	//printTree(doc.Trailer(), 0) // DEBUG

	// Find the signature element, containing the byte ranges, hashing method
	// (subfilter), and the signature itself.
	sigValue := doc.Trailer().Key("Root").Key("Perms").Key("DocMDP")
	if sigValue.IsNull() {
		return nil, errors.New("verifyPDF: could not find signature")
	}
	sigDataValue := sigValue.Key("Contents") // PKCS#7 signature
	subfilter := sigValue.Key("SubFilter")
	if sigDataValue.IsNull() || sigDataValue.Kind() != pdf.String || subfilter.IsNull() || subfilter.Kind() != pdf.Name {
		return nil, errors.New("verifyPDF: could not extract signature")
	}

	// Read signed ranges. This is very likely the range from the start of the
	// document until the signature, and then from the end of the signature to
	// the end of the document. But we can't be sure of it (it might have been
	// tampered with), so we'll calculate the hash, validate it in a later step,
	// and only continue working with the parts that were included in the hash.
	byteRangeValue := sigValue.Key("ByteRange")
	if byteRangeValue.IsNull() || byteRangeValue.Kind() != pdf.Array || byteRangeValue.Len() != 4 {
		return nil, errors.New("verifyPDF: could not find ByteRange")
	}
	byteRange := make([]int64, 4)
	for i := range byteRange {
		if byteRangeValue.Index(i).Kind() != pdf.Integer {
			return nil, errors.New("verifyPDF: invalid ByteRange type")
		}
		byteRange[i] = byteRangeValue.Index(i).Int64()
	}

	// Are these byteRange values somewhat sane?
	// Note that this is just a quick and small (incomplete) sanity check for
	// the input byte ranges. The real check is below when the verified (and
	// thus trusted) byte ranges are copied and put in a new PDF.
	if byteRange[0] != 0 || byteRange[2]+byteRange[3] != int64(len(inputPDF)) {
		return nil, errors.New("verifyPDF: byte ranges don't cover the entire PDF")
	}

	// Get the hashed data blocks.
	before := inputPDF[byteRange[0] : byteRange[0]+byteRange[1]]
	after := inputPDF[byteRange[2] : byteRange[2]+byteRange[3]]

	// Check for supported hash functions.
	if subfilter.Name() == "adbe.pkcs7.sha1" {
		// This is an old PDF, which is signed with SHA1. Unfortunately, we will
		// need to support this version for a while.
		// Let's do the hashing!
		hashInst := sha1.New()
		hashInst.Write(before)
		hashInst.Write(after)
		hash := hashInst.Sum(nil)

		// And verify the signature over the hash we just calculated.
		if err := verifySignature([]byte(sigDataValue.RawString()), pool, hash); err != nil {
			return nil, err
		}

	} else if subfilter.Name() == "adbe.pkcs7.detached" {
		// This is a newer PDF, which uses a more modern "detached" signature.
		// The signed data from the PDF is inserted into a buffer which is then
		// verified.
		data := make([]byte, len(before)+len(after))
		copy(data[:len(before)], before)
		copy(data[len(before):], after)
		if err := verifyDetachedSignature([]byte(sigDataValue.RawString()), pool, data); err != nil {
			return nil, err
		}

	} else {
		return nil, errors.New("verifyPDF: unimplemented subfilter: " + subfilter.Name())
	}

	// At this point, the data in "before" and "after" is verified so we can
	// trust it. But we can't trust the original PDF, because it might contain unsigned data -
	// so we'll build a new one from only the signed, trusted data.

	// Build a new PDF with only trusted data.
	// It would be more efficient to zero out the untrusted parts, but copying
	// the trusted parts is a bit more resistant against mistakes.
	trustedPDF := make([]byte, byteRange[2]+byteRange[3])
	copy(trustedPDF[byteRange[0]:byteRange[0]+byteRange[1]], before)
	copy(trustedPDF[byteRange[2]:byteRange[2]+byteRange[3]], after)

	return trustedPDF, nil
}

// verifySignature verifies the given signature over the specified hash,
// returning an error on any error (including verification failure).
func verifySignature(sigData []byte, pool *x509.CertPool, foundHash []byte) error {
	// Parse the PKCS#7 signature object.
	sig, err := cms.ParseSignedData(sigData)
	if err != nil {
		return err
	}

	// Verify the loaded signature.
	// Use the intermediary certificate as a root certificate.
	verifyOpts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		Roots:         pool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	}
	_, err = sig.Verify(verifyOpts)
	if err != nil {
		return err
	}

	data, err := sig.GetData() // hash of signed parts of the PDF
	if err != nil {
		return err
	}

	// Check whether the signed hash matches the hash we calculated ourselves.
	if bytes.Compare(foundHash, data) != 0 {
		return errors.New("verifySignature: could not verify signature: hash doesn't match")
	}
	return nil
}

// verifyDetachedSignature verifies the given message with the given message,
// returning an error on any error (including verification failure).
func verifyDetachedSignature(sigData []byte, pool *x509.CertPool, msg []byte) error {
	// Parse the PKCS#7 signature object.
	sig, err := cms.ParseSignedData(sigData)
	if err != nil {
		return err
	}

	// Verify the loaded signature.
	// Use the intermediary certificate as a root certificate.
	verifyOpts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		Roots:         pool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	}
	_, err = sig.VerifyDetached(msg, verifyOpts)
	return err
}

// Extracts all attributes from a PDF file for use by IRMA, by first converting
// to HTML and then parsing it.
func extractAttributes(pdfData []byte) ([]map[string]string, error) {
	// Sadly we have to write temporary files:
	// https://github.com/coolwanglu/pdf2htmlEX/issues/638

	// Remove temporary files after we're done with them (or at least try to).
	// They return an error when they fail (for whatever reason, including "does
	// not exist"), but otherwise have no side effects.
	infile, err := ioutil.TempFile(tmpDir, "duo-verified-pdf-")
	if err != nil {
		return nil, err
	}
	defer infile.Close()
	if !keepOutput {
		defer os.Remove(infile.Name())
	}
	outfile, err := ioutil.TempFile(tmpDir, "duo-verified-html-")
	if err != nil {
		return nil, err
	}
	defer outfile.Close()
	if !keepOutput {
		defer os.Remove(outfile.Name())
	}

	_, err = infile.Write(pdfData)
	if err != nil {
		return nil, err
	}
	err = infile.Close()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("pdf2htmlEX",
		"--process-nontext", "0", // don't extract images (faster!)
		infile.Name(),  // input
		outfile.Name()) // output
	if enableDebug {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	err = cmd.Run()
	if err != nil {
		return nil, &ExtractError{"run pdf2htmlEX", err}
	}

	htmlData, err := ioutil.ReadAll(outfile)
	if err != nil {
		return nil, err
	}

	// Extract raw attributes from the HTML. These are the keys as used in the
	// PDF document.
	doc := soup.HTMLParse(string(htmlData))
	body := doc.Find("body")

	// All pages are enclosed in an element with ID "page-container". The page
	// container contains the individual PDF pages.
	var container soup.Root
	for _, child := range body.Children() {
		if child.Attrs()["id"] == "page-container" {
			container = child
			break
		}
	}
	if container.Pointer == nil {
		return nil, &ExtractError{"cannot parse HTML: cannot find page container", nil}
	}

	attributeSet := make([]map[string]string, 0, 1)
	for _, page := range container.Children() {
		if page.Pointer.Type != html.ElementNode {
			continue
		}
		attributes, err := extractSinglePage(page)
		if err != nil {
			return nil, err
		}
		if attributes == nil {
			continue // e.g. last page of a list of marks where no attributes exist
		}
		attributeSet = append(attributeSet, attributes)
	}
	return attributeSet, nil
}

func extractSinglePage(page soup.Root) (map[string]string, error) {
	validPage := false
	lastKey := ""
	rawAttributes := make(map[string]string)
	for _, el := range page.FindAll("div") {
		children := el.Children()
		if lastKey == "Instelling" && len(children) == 1 && children[0].Pointer.Type == html.TextNode {
			// Sometimes, a property continues on the next line.
			// This is a heuristic to determine this case: when the previous row
			// was a valid row and this row contains just a single value, it's
			// probably a continuation.
			rawAttributes[lastKey] += " " + strings.TrimSpace(children[0].NodeValue)
			continue
		}
		lastKey = "" // not a continuation

		if len(children) == 1 && children[0].Pointer.Type == html.TextNode {
			if children[0].NodeValue == "Uittreksel uit het diplomaregister" {
				validPage = true
			}
		}

		if len(children) != 3 {
			continue
		}
		if children[0].Pointer.Type != html.TextNode || children[2].Pointer.Type != html.TextNode {
			continue
		}

		// This appears to be a valid property key
		key := strings.TrimSpace(children[0].NodeValue)
		value := strings.TrimSpace(children[2].NodeValue)
		rawAttributes[key] = value
		lastKey = key
	}

	// Transform raw attributes in IRMA attributes, with standard names and
	// value formatting.
	attributes := make(map[string]string)
	for key, value := range rawAttributes {
		switch key {
		case "Achternaam":
			attributes["familyname"] = value
		case "Tussenvoegsel":
			attributes["prefix"] = value
		case "Voorna(a)m(en)":
			attributes["firstname"] = value
		case "Geslacht":
			switch value {
			case "Man":
				attributes["gender"] = "male"
			case "Vrouw":
				attributes["gender"] = "female"
			default:
				attributes["gender"] = "unknown"
			}
		case "Geboortedatum":
			attributes["dateofbirth"] = parseDutchDate(value) // "" if parse error
		case "Soort waardedocument":
			// skip
		case "Opleiding":
			attributes["education"] = value
		case "Aard van het examen":
			// university etc. (e.g. WO Master)
			attributes["degree"] = value
		case "Profiel":
			// high school (e.g. Nieuw Profiel Natuur en Techniek)
			attributes["profile"] = value
		case "Behaald in", "Behaald op":
			date := parseDutchDate(value)
			if date == "" {
				date = parseDutchMonth(value)
			}
			if enableDebug && date == "" {
				fmt.Printf("Cannot parse date: %s\n", value)
			}
			attributes["achieved"] = date // "" if parse error
		case "Instelling":
			// Format: <name> in <city>
			// where <city> is in all caps.
			in := strings.LastIndex(value, " in ")
			if in < 0 {
				continue // cannot parse
			}
			attributes["institute"] = strings.TrimSpace(value[:in])
			attributes["city"] = strings.TrimSpace(value[in+4:]) // all uppercase
		default:
			if enableDebug && key != "" {
				fmt.Printf("Unknown property: %s = %s\n", key, value)
			}
		}
	}

	if !validPage {
		return nil, nil // no attributes found on this page
	}

	requiredAttributes := map[string]bool{
		"familyname":  true,
		"prefix":      false,
		"firstname":   true,
		"gender":      true,
		"dateofbirth": true,
		"education":   true,
		"degree":      false,
		"profile":     false,
		"achieved":    true,
		"institute":   true,
		"city":        true,
	}

	for key, required := range requiredAttributes {
		if _, ok := attributes[key]; required && !ok {
			return nil, &ExtractError{"cannot find attribute: " + key, nil}
		}
	}

	return attributes, nil
}

// List of Dutch months, as used in diploma dates.
var dutchMonths = map[string]int{
	"januari":   1,
	"februari":  2,
	"maart":     3,
	"april":     4,
	"mei":       5,
	"juni":      6,
	"juli":      7,
	"augustus":  8,
	"september": 9,
	"oktober":   10,
	"november":  11,
	"december":  12,
}

// Parse a Dutch date in the form "3 maart 1990"
func parseDutchDate(indate string) string {
	parts := strings.Fields(indate)
	if len(parts) != 3 {
		return ""
	}
	day, _ := strconv.Atoi(parts[0])
	month := dutchMonths[parts[1]]
	year, _ := strconv.Atoi(parts[2])
	if day == 0 || month == 0 || year == 0 {
		return "" // something went wrong
	}
	return fmt.Sprintf("%02d-%02d-%04d", day, month, year)
}

// Parse a Dutch month in the form "Augustus 2016"
func parseDutchMonth(indate string) string {
	parts := strings.Fields(indate)
	if len(parts) != 2 {
		return ""
	}
	month := dutchMonths[strings.ToLower(parts[0])]
	year, _ := strconv.Atoi(parts[1])
	if month == 0 || year == 0 {
		return "" // something went wrong
	}
	// Pick the first day of the month.
	return fmt.Sprintf("01-%02d-%04d", month, year)
}

// Load an X.509 certificate from a file in DER format.
func loadCertificate(path string) (*x509.Certificate, error) {
	intermediaryData, err := readFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(intermediaryData)
	if block == nil {
		return nil, errors.New("failed to read PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// Take PDF data in as a byte array, verify it, and return its attributes.
// A verification failure will result in an error.
func verifyAndExtract(pdfData []byte) ([]map[string]string, error) {
	// Load parent certificates from DUO.
	// TODO: cache this.
	pool := x509.NewCertPool()
	pattern := certDir + "/*.pem"
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, ExtractError{"read certificate dir", err}
	}
	if len(paths) == 0 {
		return nil, ExtractError{"no certificates found at " + pattern, nil}
	}
	for _, path := range paths {
		parentCert, err := loadCertificate(path)
		if err != nil {
			return nil, &ExtractError{"load parent certificate at " + path, err}
		}

		// Use these certificates as root (really, pinned) certificates.
		pool.AddCert(parentCert)
	}

	verifiedData, err := verifyPDF(pdfData, pool)
	if err != nil {
		return nil, &ExtractError{"verify PDF", err}
	}

	attributeSet, err := extractAttributes(verifiedData)
	if err != nil {
		return nil, &ExtractError{"extract attributes", err}
	}

	// TODO: check all attributes: whether all are present and non-empty.
	return attributeSet, nil
}

// Command to read attributes from PDF files and dump it's output. Used for
// debugging and such.
func cmdReadPDFs(paths []string) {
	for i, path := range paths {
		if i != 0 {
			fmt.Println()
		}
		fmt.Println("Processing:", path)
		cmdReadSinglePDF(path)
	}
}

// Command to read a single PDF file and dum it's output.
func cmdReadSinglePDF(path string) {
	pdfData, err := readFile(path)
	if err != nil {
		fmt.Println("could not read input PDF:", err)
		return
	}

	attributeSets, err := verifyAndExtract(pdfData)
	if err != nil {
		fmt.Println("could not extract attributes:", err)
		return
	}

	for _, attributes := range attributeSets {
		// Pretty-print attributes in the way they're extracted.
		var keys []string
		for key := range attributes {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		fmt.Println("extracted and verified attributes:")
		for _, key := range keys {
			fmt.Printf("  %-12s: %s\n", key, attributes[key])
		}
	}
}
