package taprootdescriptor

import (
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
	if keyStr != UnspendableKey {
		return Key{}, errors.New("invalid internal key: must use unspendable key for taproot")
	}
	return Key{Hex: UnspendableKey}, nil
}

func parseLeafScript(scriptStr string) (LeafScript, error) {
	return LeafScript{Script: scriptStr, Weight: 1}, nil
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

// ParseTaprootDescriptor parses a taproot descriptor string into a TaprootDescriptor struct
func ParseTaprootDescriptor(desc string) (TaprootDescriptor, error) {
	parts := strings.SplitN(desc[3:len(desc)-1], ",", 2)
	if len(parts) != 2 {
		return TaprootDescriptor{}, errors.New("invalid descriptor format")
	}

	internalKey, err := parseKey(parts[0])
	if err != nil {
		return TaprootDescriptor{}, err
	}

	scriptTreeStr := parts[1][1 : len(parts[1])-1] // Remove outer braces
	scriptParts, err := splitScriptTree(scriptTreeStr)
	if err != nil {
		return TaprootDescriptor{}, err
	}

	var scriptTree []LeafScript
	for _, scriptStr := range scriptParts {
		leaf, err := parseLeafScript(scriptStr)
		if err != nil {
			return TaprootDescriptor{}, err
		}
		scriptTree = append(scriptTree, leaf)
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
