package main

import (
	"fmt"
	"log"

	taprootdescriptor "github.com/tiero/taproot-descriptor"
)

func main() {
	// Example 1: Parse a simple Taproot descriptor with an empty script tree
	desc := "tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{})"
	parsed, err := taprootdescriptor.ParseTaprootDescriptor(desc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Parsed simple descriptor: %+v\n", parsed)

	// Example 2: Parse a more complex Taproot descriptor
	complexDesc := "tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),pk(e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)})"
	complexParsed, err := taprootdescriptor.ParseTaprootDescriptor(complexDesc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Parsed complex descriptor: %+v\n", complexParsed)

	// Example 3: Compile a descriptor
	compiled := taprootdescriptor.CompileDescriptor(complexParsed)
	fmt.Printf("Compiled descriptor: %s\n", compiled)

	// Example 4: Parse a Taproot descriptor with a complex script path (like VTXO)
	vtxoDesc := "tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),and_v(v:pk(e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),older(144))})"
	vtxoParsed, err := taprootdescriptor.ParseTaprootDescriptor(vtxoDesc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Parsed VTXO-like descriptor: %+v\n", vtxoParsed)
}