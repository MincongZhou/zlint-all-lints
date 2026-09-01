/*
 * zlint-all-lints
 *
 * 对输入的证书运行 zlint 全部 433 条规则，并输出一个 JSON 文件。
 * JSON 中每条规则记录都带一个 type 字段，用于区分规则归属：
 *   - "CA"   : 证书类规则（对证书真实执行）
 *   - "CRL"  : 吊销列表类规则（对证书不适用，状态标记为 NA）
 *   - "OCSP" : OCSP 响应类规则（对证书不适用，状态标记为 NA）
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

const (
	crlNotApplicable   = "CRL lint: only applicable to a revocation list (CRL), not to a certificate"
	ocspNotApplicable  = "OCSP lint: only applicable to an OCSP response, not to a certificate"
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
	Subject    string           `json:"subject"`
	TotalLints int              `json:"total_lints"`
	TypeCounts map[lintType]int `json:"type_counts"`
}

// output 是整个输出 JSON 的结构。
type output struct {
	Meta  meta        `json:"meta"`
	Lints []lintEntry `json:"lints"`
}

func main() {
	certPath := flag.String("cert", "", "path to a certificate file (PEM or DER)")
	outPath := flag.String("out", "lint_results.json", "path to the output JSON file")
	csvPath := flag.String("csv", "", "path to the output CSV file (optional, empty = no CSV)")
	pretty := flag.Bool("pretty", true, "pretty-print the output JSON")
	flag.Parse()

	if *certPath == "" {
		fmt.Fprintln(os.Stderr, "usage: zlint-all-lints -cert <cert.pem|cert.der> [-out results.json] [-csv results.csv] [-pretty=false]")
		os.Exit(1)
	}

	cert := parseCertificate(*certPath)
	registry := lint.GlobalRegistry()

	// 对证书执行全部证书类 lint（其余两类规则不会对证书执行）。
	rs := zlint.LintCertificateEx(cert, registry)

	entries := make([]lintEntry, 0, len(registry.Names()))
	counts := make(map[lintType]int)

	// 1) 证书类规则：取真实执行结果。
	certLints := registry.CertificateLints().Lints()
	counts[typeCA] = len(certLints)
	for _, l := range certLints {
		e := lintEntry{
			Name:        l.Name,
			Type:        typeCA,
			Description: l.Description,
			Citation:    l.Citation,
			Source:      string(l.Source),
			Status:      lint.NA.String(),
		}
		if res := rs.Results[l.Name]; res != nil {
			e.Status = res.Status.String()
			e.Details = res.Details
		}
		entries = append(entries, e)
	}

	// 2) CRL 类规则：对证书不适用，统一标记 NA。
	crlLints := registry.RevocationListLints().Lints()
	counts[typeCRL] = len(crlLints)
	for _, l := range crlLints {
		entries = append(entries, lintEntry{
			Name:        l.Name,
			Type:        typeCRL,
			Description: l.Description,
			Citation:    l.Citation,
			Source:      string(l.Source),
			Status:      lint.NA.String(),
			Details:     crlNotApplicable,
		})
	}

	// 3) OCSP 类规则：对证书不适用，统一标记 NA。
	ocspLints := registry.OcspResponseLints().Lints()
	counts[typeOCSP] = len(ocspLints)
	for _, l := range ocspLints {
		entries = append(entries, lintEntry{
			Name:        l.Name,
			Type:        typeOCSP,
			Description: l.Description,
			Citation:    l.Citation,
			Source:      string(l.Source),
			Status:      lint.NA.String(),
			Details:     ocspNotApplicable,
		})
	}

	// 按规则名排序，保证输出稳定。
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	out := output{
		Meta: meta{
			InputFile:  *certPath,
			Subject:    cert.Subject.String(),
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

	// 依据同样的 lint 结果，再输出一份 CSV。
	if *csvPath != "" {
		if err := writeCSV(*csvPath, entries); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write %q: %v\n", *csvPath, err)
			os.Exit(1)
		}
		fmt.Printf("output written to %s\n", *csvPath)
	}

	// 控制台摘要。
	fmt.Printf("total lints: %d (CA=%d, CRL=%d, OCSP=%d)\n",
		len(entries), counts[typeCA], counts[typeCRL], counts[typeOCSP])
	fmt.Printf("certificate lint results -> errors: %d, warnings: %d, notices: %d, passes: %d\n",
		statusCount(rs, lint.Error), statusCount(rs, lint.Warn),
		statusCount(rs, lint.Notice), statusCount(rs, lint.Pass))
	fmt.Printf("output written to %s\n", *outPath)
}

// parseCertificate 从 PEM 或 DER 文件中解析出一张证书。
func parseCertificate(path string) *x509.Certificate {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %q: %v\n", path, err)
		os.Exit(1)
	}

	der := fileBytes
	if block, _ := pem.Decode(fileBytes); block != nil {
		if block.Type != "CERTIFICATE" {
			fmt.Fprintf(os.Stderr, "unexpected PEM block type %q, want %q\n", block.Type, "CERTIFICATE")
			os.Exit(1)
		}
		der = block.Bytes
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse certificate: %v\n", err)
		os.Exit(1)
	}
	return cert
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

// statusCount 统计 ResultSet 中指定状态的证书类 lint 数量。
func statusCount(rs *zlint.ResultSet, want lint.LintStatus) int {
	n := 0
	for _, res := range rs.Results {
		if res.Status == want {
			n++
		}
	}
	return n
}
