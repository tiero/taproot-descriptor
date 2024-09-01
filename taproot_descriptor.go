package taprootdescriptor

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// UnspendableKey is the x-only pubkey of the secp256k1 base point G
const UnspendableKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

type Key struct {
	Hex string
}

type LeafScript struct {
	Script string
	Weight int
}

type TaprootDescriptor struct {
	InternalKey Key
	ScriptTree  []LeafScript
}

func parseKey(keyStr string) (Key, error) {
	decoded, err := hex.DecodeString(keyStr)
	if err != nil {
		return Key{}, fmt.Errorf("invalid key: not a valid hex string: %v", err)
	}

	switch len(decoded) {
	case 32:
		// x-only public key, this is correct for Taproot
		return Key{Hex: keyStr}, nil
	case 33:
		// compressed public key, we need to remove the prefix byte
		return Key{Hex: keyStr[2:]}, nil
	default:
		return Key{}, fmt.Errorf("invalid key length: expected 32 or 33 bytes, got %d", len(decoded))
	}
}
func splitScriptTree(scriptTreeStr string) ([]string, error) {
	var result []string
	var current strings.Builder
	depth := 0

	for _, char := range scriptTreeStr {
		switch char {
		case '(':
			depth++
			current.WriteRune(char)
		case ')':
			depth--
			current.WriteRune(char)
			if depth == 0 {
				result = append(result, current.String())
				current.Reset()
			}
		case ',':
			if depth == 0 {
				if current.Len() > 0 {
					result = append(result, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(char)
			}
		default:
			current.WriteRune(char)
		}
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	if depth != 0 {
		return nil, errors.New("mismatched parentheses in script tree")
	}

	return result, nil
}

func parseLeafScript(scriptStr string) (LeafScript, error) {
	return LeafScript{Script: strings.TrimSpace(scriptStr), Weight: 1}, nil
}

func ParseTaprootDescriptor(desc string) (TaprootDescriptor, error) {
	if !strings.HasPrefix(desc, "tr(") || !strings.HasSuffix(desc, ")") {
		return TaprootDescriptor{}, errors.New("invalid descriptor format")
	}

	content := desc[3 : len(desc)-1]
	parts := strings.SplitN(content, ",", 2)

	if len(parts) != 2 {
		return TaprootDescriptor{}, errors.New("invalid descriptor format: missing script tree")
	}

	internalKey, err := parseKey(parts[0])
	if err != nil {
		return TaprootDescriptor{}, err
	}

	scriptTreeStr := parts[1]
	if !strings.HasPrefix(scriptTreeStr, "{") || !strings.HasSuffix(scriptTreeStr, "}") {
		return TaprootDescriptor{}, errors.New("invalid script tree format")
	}
	scriptTreeStr = scriptTreeStr[1 : len(scriptTreeStr)-1]

	scriptTree := []LeafScript{} // Initialize as empty slice instead of nil
	if scriptTreeStr != "" {
		scriptParts, err := splitScriptTree(scriptTreeStr)
		if err != nil {
			return TaprootDescriptor{}, err
		}
		for _, scriptStr := range scriptParts {
			leaf, err := parseLeafScript(scriptStr)
			if err != nil {
				return TaprootDescriptor{}, err
			}
			scriptTree = append(scriptTree, leaf)
		}
	}

	return TaprootDescriptor{
		InternalKey: internalKey,
		ScriptTree:  scriptTree,
	}, nil
}

// CompileDescriptor compiles a TaprootDescriptor struct back into a descriptor string
func CompileDescriptor(desc TaprootDescriptor) string {
	scriptParts := make([]string, len(desc.ScriptTree))
	for i, leaf := range desc.ScriptTree {
		scriptParts[i] = leaf.Script
	}
	scriptTree := strings.Join(scriptParts, ",")
	return fmt.Sprintf("tr(%s,{%s})", desc.InternalKey.Hex, scriptTree)
}
