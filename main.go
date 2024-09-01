package main

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

func parseTaprootDescriptor(desc string) (TaprootDescriptor, error) {
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

func compileDescriptor(desc TaprootDescriptor) string {
	return fmt.Sprintf("Taproot output with unspendable internal key and %d script paths",
		len(desc.ScriptTree))
}

func main() {
	// Basic Taproot
	basicDesc := fmt.Sprintf("tr(%s,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)})", UnspendableKey)

	// VTXO: (Alice & Server) or (Alice after 1 day)
	vtxoDesc := fmt.Sprintf("tr(%s,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c),and_v(v:pk(59bffef74a89f39715b9f6b8a83e53a60a458d45542f20e2e2f4f7dbffafc5f8),older(144))})", UnspendableKey)

	// Boarding: (Alice & Server) or (Alice after 1 year)
	boardingDesc := fmt.Sprintf("tr(%s,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c),and_v(v:pk(59bffef74a89f39715b9f6b8a83e53a60a458d45542f20e2e2f4f7dbffafc5f8),older(52560))})", UnspendableKey)

	descriptors := []string{basicDesc, vtxoDesc, boardingDesc}

	for i, desc := range descriptors {
		parsed, err := parseTaprootDescriptor(desc)
		if err != nil {
			fmt.Printf("Error parsing descriptor %d: %v\n", i+1, err)
			continue
		}

		compiled := compileDescriptor(parsed)
		fmt.Printf("Descriptor %d: %s\n", i+1, compiled)
	}
}
