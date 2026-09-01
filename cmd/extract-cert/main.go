/*
 * extract-cert — 提取证书信息并输出为 JSON
 *
 * 输出分两部分：
 *   summary: 精选字段，便于人读（十六进制指纹、SAN 等）
 *   full:    zcrypto 标准 JSONCertificate，字段最全（所有扩展、公钥细节、未知扩展）
 *
 * 用法: go run ./cmd/extract-cert -cert <cert.pem|cert.der> [-out info.json] [-pretty=false]
 */
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	zrsa "github.com/zmap/zcrypto/rsa"
	"github.com/zmap/zcrypto/x509"
)

// summary 是人读友好的精选字段。
type summary struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SerialNumber       string   `json:"serial_number"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	ValidityDays       int      `json:"validity_days"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	SelfSigned         bool     `json:"self_signed"`
	DNSNames           []string `json:"dns_names,omitempty"`
	IPAddresses        []string `json:"ip_addresses,omitempty"`
	IsCA               bool     `json:"is_ca"`
	KeyAlgorithm       string   `json:"key_algorithm"`
	PublicKeyBits      int      `json:"public_key_bits"`
	FingerprintSHA256  string   `json:"fingerprint_sha256"`
	FingerprintSHA1    string   `json:"fingerprint_sha1"`
	SPKIFingerprint    string   `json:"spki_fingerprint_sha256"`
}

type output struct {
	InputFile string          `json:"input_file"`
	Summary   summary         `json:"summary"`
	Full      json.RawMessage `json:"full"` // zcrypto 的完整 JSONCertificate
}

func main() {
	certPath := flag.String("cert", "", "path to a certificate file (PEM or DER)")
	outPath := flag.String("out", "cert_info.json", "path to the output JSON file")
	pretty := flag.Bool("pretty", true, "pretty-print the output JSON")
	flag.Parse()

	if *certPath == "" {
		fmt.Fprintln(os.Stderr, "usage: extract-cert -cert <cert.pem|cert.der> [-out info.json] [-pretty=false]")
		os.Exit(1)
	}

	cert := parseCertificate(*certPath)

	// full: zcrypto 的 Certificate 实现了 MarshalJSON()，输出完整 JSONCertificate。
	full, err := json.Marshal(cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode full JSON: %v\n", err)
		os.Exit(1)
	}

	sum := summary{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:           cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		ValidityDays:       int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		SelfSigned:         cert.SelfSigned,
		DNSNames:           cert.DNSNames,
		IsCA:               cert.IsCA,
		KeyAlgorithm:       cert.PublicKeyAlgorithm.String(),
		FingerprintSHA256:  hexColon(cert.FingerprintSHA256),
		FingerprintSHA1:    hexColon(cert.FingerprintSHA1),
		SPKIFingerprint:    hexColon(cert.SPKIFingerprint),
	}
	for _, ip := range cert.IPAddresses {
		sum.IPAddresses = append(sum.IPAddresses, ip.String())
	}
	sum.PublicKeyBits = publicKeyBits(cert)

	out := output{
		InputFile: *certPath,
		Summary:   sum,
		Full:      full,
	}

	var jsonBytes []byte
	if *pretty {
		jsonBytes, err = json.MarshalIndent(out, "", "  ")
	} else {
		jsonBytes, err = json.Marshal(out)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode output: %v\n", err)
		os.Exit(1)
	}
	jsonBytes = append(jsonBytes, '\n')

	if err := os.WriteFile(*outPath, jsonBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %q: %v\n", *outPath, err)
		os.Exit(1)
	}
	fmt.Printf("certificate info written to %s\n", *outPath)
}

// publicKeyBits 返回公钥位长（RSA 模数 / EC 曲线位长 / Ed25519）。
// 注意: zcrypto fork 了自己的 rsa 包，所以断言用 zrsa.PublicKey 而非 crypto/rsa。
func publicKeyBits(cert *x509.Certificate) int {
	switch key := cert.PublicKey.(type) {
	case *zrsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return ed25519.PublicKeySize * 8
	default:
		return 0
	}
}

// hexColon 把字节切片格式化成大写十六进制、冒号分隔，如 AA:BB:CC。
func hexColon(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}

// parseCertificate 从 PEM 或 DER 文件解析证书。
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
