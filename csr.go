package main

import (
        "crypto/rand"
        "crypto/rsa"
        "crypto/x509"
        "crypto/x509/pkix"
        "encoding/asn1"
        "encoding/pem"
        "log"
        "os"

        "gopkg.in/alecthomas/kingpin.v1"
)

// appendRDNs appends a relativeDistinguishedNameSET to the given RDNSequence
// and returns the new value. The relativeDistinguishedNameSET contains an
// attributeTypeAndValue for each of the given values. See RFC 5280, A.1, and
// search for AttributeTypeAndValue.
func appendRDNs(in pkix.RDNSequence, values []string, oid asn1.ObjectIdentifier) pkix.RDNSequence {
        if len(values) == 0 {
                return in
        }

        s := make([]pkix.AttributeTypeAndValue, len(values))
        for i, value := range values {
                s[i].Type = oid
                s[i].Value = value
        }

        return append(in, s)
}

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

var (
        cn    = kingpin.Flag("cn", "Server common name").Required().Short('d').String()
        o     = kingpin.Flag("org", "Organisation").Required().Short('o').String()
        l     = kingpin.Flag("loc", "Locality").Default("Brno").Short('l').String()
        st    = kingpin.Flag("st", "State").Default("Czech Republic").Short('s').String()
        c     = kingpin.Flag("country", "Country").Default("CZ").Short('c').String()
        email = kingpin.Flag("email", "Email").Required().Short('e').String()
)

func main() {

        kingpin.Version("0.0.1")
        kingpin.Parse()

        log.Printf("Would do cn: %s o: %s l: %s st: %s c: %s email: %s\n", *cn, *o, *l, *st, *c, *email)

        // generate private key
        privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                log.Fatalln(err)
        }

        var subject = &pkix.Name{
                CommonName:   *cn,
                Country:      []string{*c},
                Organization: []string{*o},
                Locality:     []string{*l},
                Province:     []string{*st},
        }

        rawSubject := subject.ToRDNSequence()
        rawSubject = appendRDNs(rawSubject, []string{*email}, oidEmailAddress)
        asn1Subj, err := asn1.Marshal(rawSubject)

        var csrtemplate = &x509.CertificateRequest{
                RawSubject:         asn1Subj,
                SignatureAlgorithm: x509.SHA256WithRSA,
        }

        csr, err := x509.CreateCertificateRequest(rand.Reader, csrtemplate, privatekey)
        if err != nil {
                log.Println(err)
        }

        // save private key
        keyfile, err := os.Create(*cn + ".key")
        defer keyfile.Close()
        if err != nil {
                log.Println(err)
        }

        pem.Encode(keyfile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)})

        // save csr
        csrfile, err := os.Create(*cn + ".csr")
        defer csrfile.Close()
        if err != nil {
                log.Println(err)
        }
        pem.Encode(csrfile, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

}
