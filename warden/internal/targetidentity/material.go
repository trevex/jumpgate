package targetidentity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

func normalizeSuppliedCA(kind TrustAnchorKind, material string) (string, string, string, error) {
	switch kind {
	case AnchorTLSCA:
		block, rest := pem.Decode([]byte(material))
		if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" {
			return "", "", "", ErrInvalidRequest
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			return "", "", "", ErrInvalidRequest
		}
		sum := sha256.Sum256(block.Bytes)
		return "x509", "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), material, nil
	case AnchorSSHHostCA:
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(material))
		if err != nil {
			return "", "", "", ErrInvalidRequest
		}
		return key.Type(), ssh.FingerprintSHA256(key), material, nil
	default:
		return "", "", "", ErrInvalidRequest
	}
}
