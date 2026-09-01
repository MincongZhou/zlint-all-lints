/*
 * zlint-all-lints
 *
 * 对输入的 PKI 对象（证书 / CRL / OCSP 响应）运行 zlint 全部规则，并输出一个 JSON 文件。
 *
 * 输入按官方 CLI 的顺序逐级试解析：证书 → CRL → OCSP；
 * 输入是哪类对象，就真实执行哪类规则，其余两类规则标 NA；
 * 输出总条数不变（证书类 + CRL 类 + OCSP 类全部枚举）。
 *
 * JSON 中每条规则记录都带一个 type 字段，用于区分规则归属：
 *   - "CA"   : 证书类规则
 *   - "CRL"  : 吊销列表类规则
 *   - "OCSP" : OCSP 响应类规则
 *
 * 用法:
 *   zlint-all-lints -cert <file.pem|file.der> [-type cert|crl|ocsp|auto]
 *                   [-out results.json] [-csv results.csv] [-pretty=false]
 */
package main

import (
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"sort"

	"golang.org/x/crypto/ocsp"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
)

// lintType 是规则所属对象类型。
type lintType string

const (
	typeCA   lintType = "CA"
	typeCRL  lintType = "CRL"
	typeOCSP lintType = "OCSP"
)

// objectKind 是输入对象的实际类型。
type objectKind string

const (
	kindCert objectKind = "cert"
	kindCRL  objectKind = "crl"
	kindOCSP objectKind = "ocsp"
)

// lintEntry 是输出 JSON 中一条规则的记录。
type lintEntry struct {
	Name        string   `json:"name"`
	Type        lintType `json:"type"`
	Description string   `json:"description,omitempty"`
	Citation    string   `json:"citation,omitempty"`
	Source      string   `json:"source"`
	Status      string   `json:"status"`
	Details     string   `json:"details,omitempty"`
}

// meta 是输出 JSON 的元信息。
type meta struct {
	InputFile  string           `json:"input_file"`
	InputType  objectKind       `json:"input_type"`
	Subject    string           `json:"subject"`
	TotalLints int              `json:"total_lints"`
	TypeCounts map[lintType]int `json:"type_counts"`
}

// output 是整个输出 JSON 的结构。
type output struct {
	Meta  meta        `json:"meta"`
	Lints []lintEntry `json:"lints"`
}

// naDetails 返回"规则类型 ruleType 不适用于输入对象 kind"时的说明文案。
func naDetails(ruleType lintType, kind objectKind) string {
	switch {
	case ruleType == typeCA && kind == kindCRL:
		return "certificate lint: only applicable to a certificate, not to a revocation list (CRL)"
	case ruleType == typeCA && kind == kindOCSP:
		return "certificate lint: only applicable to a certificate, not to an OCSP response"
	case ruleType == typeCRL && kind == kindCert:
		return "CRL lint: only applicable to a revocation list (CRL), not to a certificate"
	case ruleType == typeCRL && kind == kindOCSP:
		return "CRL lint: only applicable to a revocation list (CRL), not to an OCSP response"
	case ruleType == typeOCSP && kind == kindCert:
		return "OCSP lint: only applicable to an OCSP response, not to a certificate"
	case ruleType == typeOCSP && kind == kindCRL:
		return "OCSP lint: only applicable to an OCSP response, not to a revocation list (CRL)"
	}
	return ""
}

func main() {
	certPath := flag.String("cert", "", "path to a PKI object file (PEM or DER): certificate / CRL / OCSP response")
	forceType := flag.String("type", "auto", "force input type: cert | crl | ocsp | auto (default auto)")
	outPath := flag.String("out", "lint_results.json", "path to the output JSON file")
	csvPath := flag.String("csv", "", "path to the output CSV file (optional, empty = no CSV)")
	pretty := flag.Bool("pretty", true, "pretty-print the output JSON")
	flag.Parse()

	if *certPath == "" {
		fmt.Fprintln(os.Stderr, "usage: zlint-all-lints -cert <file.pem|file.der> [-type cert|crl|ocsp|auto] [-out results.json] [-csv results.csv] [-pretty=false]")
		os.Exit(1)
	}

	kind, cert, crl, resp := classify(*certPath, *forceType)
	registry := lint.GlobalRegistry()

	// 对实际解析出的对象执行对应类别的全部 lint。
	var rs *zlint.ResultSet
	switch kind {
	case kindCert:
		rs = zlint.LintCertificateEx(cert, registry)
	case kindCRL:
		rs = zlint.LintRevocationListEx(crl, registry)
	case kindOCSP:
		rs = zlint.LintOcspResponseEx(resp, registry)
	}

	// 三类规则全部枚举；只有与输入对象同类的规则取真实结果，其余标 NA。
	certLints := registry.CertificateLints().Lints()
	crlLints := registry.RevocationListLints().Lints()
	ocspLints := registry.OcspResponseLints().Lints()

	entries := make([]lintEntry, 0, len(certLints)+len(crlLints)+len(ocspLints))
	counts := map[lintType]int{
		typeCA:   len(certLints),
		typeCRL:  len(crlLints),
		typeOCSP: len(ocspLints),
	}

	// results 只对与输入对象同类的规则非空。
	var results map[string]*lint.LintResult
	if rs != nil {
		results = rs.Results
	}

	addEntry := func(ruleType lintType, name, desc, citation, source string, applies bool) {
		e := lintEntry{
			Name:        name,
			Type:        ruleType,
			Description: desc,
			Citation:    citation,
			Source:      source,
			Status:      lint.NA.String(),
		}
		if applies {
			if res := results[name]; res != nil {
				e.Status = res.Status.String()
				e.Details = res.Details
			}
		} else {
			e.Details = naDetails(ruleType, kind)
		}
		entries = append(entries, e)
	}

	for _, l := range certLints {
		addEntry(typeCA, l.Name, l.Description, l.Citation, string(l.Source), kind == kindCert)
	}
	for _, l := range crlLints {
		addEntry(typeCRL, l.Name, l.Description, l.Citation, string(l.Source), kind == kindCRL)
	}
	for _, l := range ocspLints {
		addEntry(typeOCSP, l.Name, l.Description, l.Citation, string(l.Source), kind == kindOCSP)
	}

	// 按规则名排序，保证输出稳定。
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	out := output{
		Meta: meta{
			InputFile:  *certPath,
			InputType:  kind,
			Subject:    subjectOf(kind, cert, crl),
			TotalLints: len(entries),
			TypeCounts: counts,
		},
		Lints: entries,
	}

	var jsonBytes []byte
	var err error
	if *pretty {
		jsonBytes, err = json.MarshalIndent(out, "", "  ")
	} else {
		jsonBytes, err = json.Marshal(out)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode JSON: %v\n", err)
		os.Exit(1)
	}
	jsonBytes = append(jsonBytes, '\n')

	if err := os.WriteFile(*outPath, jsonBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %q: %v\n", *outPath, err)
		os.Exit(1)
	}

	if *csvPath != "" {
		if err := writeCSV(*csvPath, entries); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write %q: %v\n", *csvPath, err)
			os.Exit(1)
		}
		fmt.Printf("output written to %s\n", *csvPath)
	}

	fmt.Printf("input type: %s\ntotal lints: %d (CA=%d, CRL=%d, OCSP=%d)\n",
		kind, len(entries), counts[typeCA], counts[typeCRL], counts[typeOCSP])
	if rs != nil {
		fmt.Printf("%s lint results -> errors: %d, warnings: %d, notices: %d, passes: %d\n",
			kind, statusCount(rs, lint.Error), statusCount(rs, lint.Warn),
			statusCount(rs, lint.Notice), statusCount(rs, lint.Pass))
	}
	fmt.Printf("output written to %s\n", *outPath)
}

// readDER 读取文件并返回裸 DER 字节：PEM 则解出第一个块（不限块类型，交给后续解析判定），DER/base64 则直接使用。
func readDER(path string) []byte {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %q: %v\n", path, err)
		os.Exit(1)
	}
	if block, _ := pem.Decode(fileBytes); block != nil {
		return block.Bytes
	}
	return fileBytes
}

// classify 按官方 CLI 的顺序（证书 → CRL → OCSP）逐级试解析输入文件。
// force 可强制指定类型（cert / crl / ocsp），跳过自动检测。
func classify(path, force string) (objectKind, *x509.Certificate, *x509.RevocationList, *ocsp.Response) {
	data := readDER(path)

	switch force {
	case "cert":
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse input as certificate: %v\n", err)
			os.Exit(1)
		}
		return kindCert, cert, nil, nil
	case "crl":
		crl, err := x509.ParseRevocationList(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse input as CRL: %v\n", err)
			os.Exit(1)
		}
		return kindCRL, nil, crl, nil
	case "ocsp":
		resp, err := ocsp.ParseResponse(data, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse input as OCSP response: %v\n", err)
			os.Exit(1)
		}
		return kindOCSP, nil, nil, resp
	case "", "auto":
		// 自动检测：证书 → CRL → OCSP
	default:
		fmt.Fprintf(os.Stderr, "unknown -type %q, want cert|crl|ocsp|auto\n", force)
		os.Exit(1)
	}

	var errs []error
	if cert, err := x509.ParseCertificate(data); err == nil {
		return kindCert, cert, nil, nil
	} else {
		errs = append(errs, fmt.Errorf("parsing as certificate: %v", err))
	}
	if crl, err := x509.ParseRevocationList(data); err == nil {
		return kindCRL, nil, crl, nil
	} else {
		errs = append(errs, fmt.Errorf("parsing as CRL: %v", err))
	}
	if resp, err := ocsp.ParseResponse(data, nil); err == nil {
		return kindOCSP, nil, nil, resp
	} else {
		errs = append(errs, fmt.Errorf("parsing as OCSP response: %v", err))
	}
	fmt.Fprintf(os.Stderr, "unable to parse input as any known type, errors: %v\n", errs)
	os.Exit(1)
	return "", nil, nil, nil
}

// subjectOf 返回 meta.subject 的展示值：证书取 Subject，CRL 取 Issuer，OCSP 无对应字段留空。
func subjectOf(kind objectKind, cert *x509.Certificate, crl *x509.RevocationList) string {
	switch kind {
	case kindCert:
		return cert.Subject.String()
	case kindCRL:
		return crl.Issuer.String()
	}
	return ""
}

// writeCSV 将全部 lint 结果写为 CSV，列结构与 JSON 的 lintEntry 字段一一对应。
func writeCSV(path string, entries []lintEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{"name", "type", "description", "citation", "source", "status", "details"}); err != nil {
		return err
	}
	for _, e := range entries {
		if err := w.Write([]string{
			e.Name,
			string(e.Type),
			e.Description,
			e.Citation,
			e.Source,
			e.Status,
			e.Details,
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

// statusCount 统计 ResultSet 中指定状态的 lint 数量。
func statusCount(rs *zlint.ResultSet, want lint.LintStatus) int {
	n := 0
	for _, res := range rs.Results {
		if res.Status == want {
			n++
		}
	}
	return n
}
