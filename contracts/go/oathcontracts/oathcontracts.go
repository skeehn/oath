package oathcontracts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
)

func writeString(buffer *bytes.Buffer, value string) {
	encoded, _ := json.Marshal(value)
	encoded = bytes.ReplaceAll(encoded, []byte(`\u003c`), []byte("<"))
	encoded = bytes.ReplaceAll(encoded, []byte(`\u003e`), []byte(">"))
	encoded = bytes.ReplaceAll(encoded, []byte(`\u0026`), []byte("&"))
	encoded = bytes.ReplaceAll(encoded, []byte(`\u2028`), []byte("\u2028"))
	encoded = bytes.ReplaceAll(encoded, []byte(`\u2029`), []byte("\u2029"))
	buffer.Write(encoded)
}

func writeCanonical(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case bool:
		if typed {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case string:
		writeString(buffer, typed)
	case json.Number:
		if strings.ContainsAny(typed.String(), ".eE") {
			return errors.New("oath-json-v1 accepts only JSON integers")
		}
		if _, err := typed.Int64(); err != nil {
			return err
		}
		buffer.WriteString(typed.String())
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := writeCanonical(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			writeString(buffer, key)
			buffer.WriteByte(':')
			if err := writeCanonical(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		return errors.New("unsupported oath-json-v1 value")
	}
	return nil
}

func CanonicalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	if err := writeCanonical(&buffer, value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func VerifySignedDocument(document []byte) (bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return false, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return false, errors.New("signed document contains trailing JSON")
		}
		return false, err
	}
	detached, ok := payload["signature"].(map[string]any)
	if !ok || detached["algorithm"] != "ed25519" {
		return false, nil
	}
	publicKeyText, ok := detached["public_key"].(string)
	if !ok {
		return false, nil
	}
	signatureText, ok := detached["signature"].(string)
	if !ok {
		return false, nil
	}
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyText)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return false, nil
	}
	signature, err := base64.StdEncoding.DecodeString(signatureText)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false, nil
	}
	payload["signature"] = nil
	canonical, err := CanonicalJSON(payload)
	if err != nil {
		return false, err
	}
	signed := canonical
	switch detached["canonicalization"] {
	case "oath-json-v1":
		if _, present := detached["domain"]; present {
			return false, nil
		}
	case "oath-json-v1+oath-domain-sha256-v1":
		domain, ok := detached["domain"].(string)
		if !ok || domain == "" {
			return false, nil
		}
		payloadDigest := sha256.Sum256(canonical)
		preimage := bytes.NewBufferString("oath-domain-signature-v1\x00")
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len([]byte(domain))))
		preimage.Write(length[:])
		preimage.WriteString(domain)
		preimage.Write(payloadDigest[:])
		digest := sha256.Sum256(preimage.Bytes())
		signed = digest[:]
	default:
		return false, nil
	}
	return ed25519.Verify(publicKey, signed, signature), nil
}
