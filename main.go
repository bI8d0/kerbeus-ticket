//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func writePrincipal(buf *bytes.Buffer, realm string, components []string) {
	binary.Write(buf, binary.BigEndian, uint32(1))
	binary.Write(buf, binary.BigEndian, uint32(len(components)))
	binary.Write(buf, binary.BigEndian, uint32(len(realm)))
	buf.WriteString(realm)
	for _, comp := range components {
		binary.Write(buf, binary.BigEndian, uint32(len(comp)))
		buf.WriteString(comp)
	}
}

func writeKeyblock(buf *bytes.Buffer, keyType int32, keyData []byte) {
	// In ccache format 0504, keytype is 16 bits, but etype padding is required
	binary.Write(buf, binary.BigEndian, uint16(keyType))
	binary.Write(buf, binary.BigEndian, uint16(0)) // etype (padding in some versions)
	binary.Write(buf, binary.BigEndian, uint16(len(keyData)))
	buf.Write(keyData)
}

func buildMITCCache(ticket messages.Ticket, encPart messages.EncKDCRepPart, clientName types.PrincipalName, realm string) ([]byte, error) {
	buf := new(bytes.Buffer)

	// === Header ===
	// Version 0x0504
	binary.Write(buf, binary.BigEndian, uint16(0x0504))
	// Header length (12 bytes for DeltaTime tag)
	binary.Write(buf, binary.BigEndian, uint16(12))
	// Header tag: DeltaTime (tag=1, length=8, value=0)
	binary.Write(buf, binary.BigEndian, uint16(1)) // tag
	binary.Write(buf, binary.BigEndian, uint16(8)) // length
	binary.Write(buf, binary.BigEndian, uint32(0)) // time offset seconds
	binary.Write(buf, binary.BigEndian, uint32(0)) // time offset microseconds

	// === Default Principal ===
	writePrincipal(buf, realm, clientName.NameString)

	// === Credential ===
	// Client principal
	writePrincipal(buf, realm, clientName.NameString)

	// Server principal
	writePrincipal(buf, realm, ticket.SName.NameString)

	// Session key
	writeKeyblock(buf, int32(encPart.Key.KeyType), encPart.Key.KeyValue)

	// Timestamps (uint32 big-endian)
	binary.Write(buf, binary.BigEndian, uint32(encPart.AuthTime.Unix()))
	binary.Write(buf, binary.BigEndian, uint32(encPart.StartTime.Unix()))
	binary.Write(buf, binary.BigEndian, uint32(encPart.EndTime.Unix()))
	binary.Write(buf, binary.BigEndian, uint32(encPart.RenewTill.Unix()))

	// is_skey (1 byte)
	buf.WriteByte(0)

	// Ticket flags (exactly 4 bytes)
	flags := encPart.Flags.Bytes
	if len(flags) < 4 {
		padded := make([]byte, 4)
		copy(padded[4-len(flags):], flags)
		flags = padded
	}
	buf.Write(flags[:4])

	// Addresses (count = 0)
	binary.Write(buf, binary.BigEndian, uint32(0))

	// Authdata (count = 0)
	binary.Write(buf, binary.BigEndian, uint32(0))

	// Ticket (ASN.1 DER)
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		return nil, err
	}
	binary.Write(buf, binary.BigEndian, uint32(len(ticketBytes)))
	buf.Write(ticketBytes)

	// Second ticket (length = 0)
	binary.Write(buf, binary.BigEndian, uint32(0))

	return buf.Bytes(), nil
}

func generateCCacheFromCredentials(domain, username, password, kdcHost, outputDir string) error {
	domain = strings.ToUpper(domain)

	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = domain
	cfg.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"}
	cfg.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"}
	cfg.LibDefaults.PermittedEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"}
	cfg.LibDefaults.UDPPreferenceLimit = 1

	cfg.Realms = []config.Realm{{
		Realm:         domain,
		KDC:           []string{fmt.Sprintf("%s:88", kdcHost)},
		DefaultDomain: domain,
	}}
	cfg.DomainRealm = map[string]string{
		strings.ToLower(domain):       domain,
		"." + strings.ToLower(domain): domain,
	}

	cl := client.NewWithPassword(username, domain, password, cfg, client.DisablePAFXFAST(true))

	// Build ASReq manually
	asReq, err := messages.NewASReqForTGT(domain, cfg, cl.Credentials.CName())
	if err != nil {
		return fmt.Errorf("error creating ASReq: %v", err)
	}

	asRep, err := cl.ASExchange(domain, asReq, 0)
	if err != nil {
		return fmt.Errorf("error in AS Exchange: %v", err)
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("error creating directory: %v", err)
	}

	ccacheData, err := buildMITCCache(asRep.Ticket, asRep.DecryptedEncPart, cl.Credentials.CName(), domain)
	if err != nil {
		return fmt.Errorf("error building ccache: %v", err)
	}

	ccacheFile := fmt.Sprintf("%s/%s.ccache", outputDir, username)
	if err := os.WriteFile(ccacheFile, ccacheData, 0600); err != nil {
		return fmt.Errorf("error writing ccache: %v", err)
	}

	fmt.Printf("✓ ccache generated: %s\n", ccacheFile)
	return nil
}

func printBanner() {
	fmt.Println()
	fmt.Println("  ╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("  ║                                                               ║")
	fmt.Println("  ║   ██╗  ██╗███████╗██████╗ ██████╗ ███████╗██╗   ██╗███████╗   ║")
	fmt.Println("  ║   ██║ ██╔╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║   ██║██╔════╝   ║")
	fmt.Println("  ║   █████╔╝ █████╗  ██████╔╝██████╔╝█████╗  ██║   ██║███████╗   ║")
	fmt.Println("  ║   ██╔═██╗ ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║   ██║╚════██║   ║")
	fmt.Println("  ║   ██║  ██╗███████╗██║  ██║██████╔╝███████╗╚██████╔╝███████║   ║")
	fmt.Println("  ║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝   ║")
	fmt.Println("  ║                                                               ║")
	fmt.Println("  ║           Kerberos ticket TGT ccache Generator v1.0           ║")
	fmt.Println("  ║                           By bI8d0                            ║")
	fmt.Println("  ╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Kerberos ticket TGT ccache Generator v1.0
USAGE:
  ./kerbeus-ticket -host <host> -domain <domain> -user <user> -pass <password>
`)
	}
}

func main() {
	kdcHost := flag.String("host", "", "IP or name of the KDC server")
	domain := flag.String("domain", "", "Kerberos domain")
	username := flag.String("user", "", "Username")
	password := flag.String("pass", "", "Password")
	outputDir := flag.String("o", "./ccache", "Output directory")
	flag.Parse()

	if *kdcHost == "" || *domain == "" || *username == "" || *password == "" {
		fmt.Fprintf(os.Stderr, "❌ Error: Missing required parameters\n\n")
		flag.Usage()
		os.Exit(1)
	}

	printBanner()

	fmt.Printf("🔐 Generating TGT ccache...\n\n")
	fmt.Printf("   Host: %s\n", *kdcHost)
	fmt.Printf("   Domain: %s\n", *domain)
	fmt.Printf("   User: %s\n\n", *username)

	if err := generateCCacheFromCredentials(*domain, *username, *password, *kdcHost, *outputDir); err != nil {
		log.Fatalf("❌ Error: %v", err)
	}

	fmt.Printf("\n✓ TGT ticket generated successfully\n")
	absOutputDir, _ := filepath.Abs(*outputDir)
	ccachePath := filepath.Join(absOutputDir, *username+".ccache")
	fmt.Printf("✓ Export: export KRB5CCNAME=%s\n", ccachePath)
	fmt.Printf("✓ Example: nxc ldap %s -u %s -k --use-kcache\n", *kdcHost, *username)
}
