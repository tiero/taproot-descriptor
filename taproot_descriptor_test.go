package taprootdescriptor

import (
	"reflect"
	"testing"
)

func TestParseTaprootDescriptor(t *testing.T) {
	tests := []struct {
		name     string
		desc     string
		expected TaprootDescriptor
		wantErr  bool
	}{
		{
			name: "Basic Taproot",
			desc: "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)})",
			expected: TaprootDescriptor{
				InternalKey: Key{Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
				ScriptTree: []LeafScript{
					{Script: "pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)", Weight: 1},
				},
			},
			wantErr: false,
		},
		{
			name: "VTXO",
			desc: "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c),and_v(v:pk(59bffef74a89f39715b9f6b8a83e53a60a458d45542f20e2e2f4f7dbffafc5f8),older(144))})",
			expected: TaprootDescriptor{
				InternalKey: Key{Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
				ScriptTree: []LeafScript{
					{Script: "pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)", Weight: 1},
					{Script: "and_v(v:pk(59bffef74a89f39715b9f6b8a83e53a60a458d45542f20e2e2f4f7dbffafc5f8),older(144))", Weight: 1},
				},
			},
			wantErr: false,
		},
		{
			name: "Boarding",
			desc: "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c),and_v(v:pk(59bffef74a89f39715b9f6b8a83e53a60a458d45542f20e2e2f4f7dbffafc5f8),older(52560))})",
			expected: TaprootDescriptor{
				InternalKey: Key{Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
				ScriptTree: []LeafScript{
					{Script: "pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)", Weight: 1},
					{Script: "and_v(v:pk(59bffef74a89f39715b9f6b8a83e53a60a458d45542f20e2e2f4f7dbffafc5f8),older(52560))", Weight: 1},
				},
			},
			wantErr: false,
		},
		{
			name:     "Invalid Key",
			desc:     "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798G,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)})",
			expected: TaprootDescriptor{},
			wantErr:  true,
		},
		{
			name:     "Invalid Descriptor Format",
			desc:     "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
			expected: TaprootDescriptor{},
			wantErr:  true,
		},

		{
			name:     "Invalid Descriptor Format - Missing Script Tree",
			desc:     "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
			expected: TaprootDescriptor{},
			wantErr:  true,
		},
		{
			name: "Valid Empty Script Tree",
			desc: "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{})",
			expected: TaprootDescriptor{
				InternalKey: Key{Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
				ScriptTree:  []LeafScript{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTaprootDescriptor(tt.desc)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTaprootDescriptor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ParseTaprootDescriptor() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCompileDescriptor(t *testing.T) {
	tests := []struct {
		name     string
		desc     TaprootDescriptor
		expected string
	}{
		{
			name: "Basic Taproot",
			desc: TaprootDescriptor{
				InternalKey: Key{Hex: UnspendableKey},
				ScriptTree: []LeafScript{
					{Script: "pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)", Weight: 1},
				},
			},
			expected: "tr(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)})",
		},
		{
			name: "VTXO",
			desc: TaprootDescriptor{
				InternalKey: Key{Hex: UnspendableKey},
				ScriptTree: []LeafScript{
					{Script: "pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)", Weight: 1},
					{Script: "and_v(v:pk(59bffef74a89f39715b9f6b8a83e53a60a458d45542f20e2e2f4f7dbffafc5f8),older(144))", Weight: 1},
				},
			},
			expected: "tr(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c),and_v(v:pk(59bffef74a89f39715b9f6b8a83e53a60a458d45542f20e2e2f4f7dbffafc5f8),older(144))})",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompileDescriptor(tt.desc)
			if got != tt.expected {
				t.Errorf("compileDescriptor() = %v, want %v", got, tt.expected)
			}
		})
	}
}
