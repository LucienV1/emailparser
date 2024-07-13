package EmailParser

import (
	"errors"
	"net"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

var commondomains = map[string]bool{
	"gmail.com.":                  true,
	"yahoo.com.":                  true,
	"hotmail.com.":                true,
	"outlook.com.":                true,
	"icloud.com.":                 true,
	"protonmail.com.":             true,
	"proton.me.":                  true,
	"pm.me.":                      true,
	"zoho.com.":                   true,
	"yandex.com.":                 true,
	"gmx.com.":                    true,
	"mail.com.":                   true,
	"email.com.":                  true,
	"gmx.de.":                     true,
	"yahoo.co.jp.":                true,
	"hey.com.":                    true,
	"fastmail.com.":               true,
	"purelymail.com.":             true,
	"altostrat.com.":              false,
	"examplepetstore.com.":        false,
	"example-pet-store.com.":      false,
	"myownpersonaldomain.com.":    false,
	"my-own-personal-domain.com.": false,
	"cymbalgroup.com.":            false,
	"example.com.":                false,
	"example.net.":                false,
	"example.org.":                false,
	"example.edu.":                false,
	"test.":                       false,
	"example.":                    false,
	"invalid.":                    false,
	"localhost.":                  false,
	"local.":                      false,
	"onion.":                      false,
	"xn--kgbechtv.":               false,
	"xn--hgbk6aj7f53bba.":         false,
	"xn--0zwm56d.":                false,
	"xn--g6w251d.":                false,
	"xn--80akhbyknj4f.":           false,
	"xn--11b5bs3a9aj6g.":          false,
	"xn--jxalpdlp.":               false,
	"xn--9t4b11yi5a.":             false,
	"xn--deba0ad.":                false,
	"xn--zckzah.":                 false,
	"xn--hlcj6aya9esc7a.":         false,
}
var escapeneededinquotes = map[string]bool{
	`"`: true,
	`\`: true,
}
var disallowed = map[string]bool{
	"\x00": true,
	"\x01": true,
	"\x02": true,
	"\x03": true,
	"\x04": true,
	"\x05": true,
	"\x06": true,
	"\x07": true,
	"\x08": true,
	"\x09": true,
	"\x0A": true,
	"\x0B": true,
	"\x0C": true,
	"\x0D": true,
	"\x0E": true,
	"\x0F": true,
	"\x10": true,
	"\x11": true,
	"\x12": true,
	"\x13": true,
	"\x14": true,
	"\x15": true,
	"\x16": true,
	"\x17": true,
	"\x18": true,
	"\x19": true,
	"\x1A": true,
	"\x1B": true,
	"\x1C": true,
	"\x1D": true,
	"\x1E": true,
	"\x1F": true,
	"\x20": true,
	"\x22": true,
	"\x28": true,
	"\x29": true,
	"\x2E": true,
	"\x3A": true,
	"\x3B": true,
	"\x3C": true,
	"\x3E": true,
	"\x3F": true,
	"\x40": true,
	"\x5B": true,
	"\x5C": true,
	"\x5D": true,
}

var ErrPunycodeConversion error = errors.New("punycode conversion failed")
var ErrDomainOnly error = errors.New("domain only")

func ValidateDomainOfEmail(email string) (bool, error) {
	if !strings.Contains(email, "@") {
		return false, nil
	}
	output := strings.Split(email, "@")
	domain := output[len(output)-1]
	if regexp.MustCompile(`^\[[^ghijklmnopqrstuvwxyz\[\]]*\]$`).MatchString(domain) {
		domain = strings.Replace(domain, "[", "", 1)
		domain = strings.Replace(domain, "]", "", len(domain))
		i := net.ParseIP(domain)
		if i == nil {
			return false, nil
		} else if i.IsPrivate() {
			return false, nil
		}
		return true, nil
	}
	idn, err := idna.ToASCII(domain)
	if err != nil {
		return false, ErrPunycodeConversion
	}
	if strings.Index(idn, ".") != len(idn) {
		idn = idn + "."
	}
	if _, accept := commondomains[idn]; accept {
		return true, nil
	} else if !accept {
		return false, nil
	}
	if len(idn) <= 0 || len(idn) >= 255 || strings.Contains(idn, " ") || strings.Contains(idn, "..") || strings.Contains(idn, "-.") || strings.Contains(idn, ".-") || strings.Index(idn, ".") == 0 {
		return false, nil
	}
	if len(idn) >= 255 {
		return false, nil
	}
	var mxhost []*net.MX
	mxhost, err = net.LookupMX(idn)
	mxhostname := mxhost[0].Host
	if err != nil {
		return false, nil
	}
	mxaddr, err := net.LookupIP(mxhostname)
	if err != nil {
		return false, nil
	}
	num := 0
	for num <= len(mxaddr) {
		ip := net.ParseIP(mxaddr[num].String())
		if ip.IsPrivate() {
			return false, nil
		} else {
			num++
		}
	}
	return true, nil
}

func ValidateDomain(input string) (bool, error) {
	if strings.Contains(input, "@") {
		return false, ErrDomainOnly
	}
	if regexp.MustCompile(`^\[[^ghijklmnopqrstuvwxyz\[\]]*\]$`).MatchString(input) {
		input = strings.Replace(input, "[", "", 1)
		b := strings.LastIndexAny(input, "]")
		input = strings.Replace(input, "]", "", b)
		if regexp.MustCompile(`^IPv6:`).MatchString(input) {
			input = strings.Replace(input, "IPv6:", "", 1)
			if regexp.MustCompile(`::`).MatchString(input) {
				return false, nil
			}
			i := net.ParseIP(input)
			if i == nil {
				return false, nil
			} else if i.IsPrivate() {
				return false, nil
			}
			return true, nil
		}
		i := net.ParseIP(input)
		if i == nil {
			return false, nil
		} else if i.IsPrivate() {
			return false, nil
		}
		return true, nil
	}
	idn, err := idna.ToASCII(input)
	if err != nil {
		return false, ErrPunycodeConversion
	}
	if strings.Index(idn, ".") != len(idn) {
		idn = idn + "."
	}
	if _, accept := commondomains[idn]; accept {
		return true, nil
	} else if !accept {
		return false, nil
	}
	if len(idn) <= 0 || len(idn) >= 255 || strings.Contains(idn, " ") || strings.Contains(idn, "..") || strings.Contains(idn, "-.") || strings.Contains(idn, ".-") || strings.Index(idn, ".") == 0 {
		return false, nil
	}
	if len(idn) >= 255 {
		return false, nil
	}
	var mxhost []*net.MX
	mxhost, err = net.LookupMX(idn)
	mxhostname := mxhost[0].Host
	if err != nil {
		return false, nil
	}
	mxaddr, err := net.LookupIP(mxhostname)
	if err != nil {
		return false, nil
	}
	num := 0
	for num <= len(mxaddr) {
		ip := net.ParseIP(mxaddr[num].String())
		if ip.IsPrivate() {
			return false, nil
		} else {
			num++
		}
	}
	return true, nil
}

func ValidateLocalPartOfEmail(e string) (bool, error) {
	lastat := strings.LastIndexAny(e, "@")
	if lastat == -1 {
		return false, nil
	}
	localpart := e[:lastat]
	if len(localpart) <= 0 || len(localpart) > 64 {
		return false, nil
	}
	l := strings.Split(localpart, "")
	if l[len(l)-1] == `"` && l[0] == `"` {
		cb := len(l) - 1
		for cb >= 0 && l[cb] != "" {
			if !lpQuoteString(l, cb) {
				return false, nil
			}
			cb--
		}
	} else {
		if l[0] == "." {
			return false, nil
		}
		if l[0] == "(" {
			cc := strings.Index(strings.Join(l, ""), ")")
			if cc == -1 {
				return false, nil
			} else if cc >= 0 {
				l = l[cc:]
			}
		}
		cb := len(l) - 1
		if l[cb] == ")" {
			cc := strings.Index(strings.Join(l, ""), "()")
			if cc == -1 {
				return false, nil
			} else if cc >= 0 {
				l = l[:cc]
			}
		}
		if l[cb] == "." {
			return false, nil
		}
		for cb >= 0 && l[cb] != "" {
			if !lpByteCheck(l, cb) {
				return false, nil
			} else {
				cb--
			}
		}
	}
	return true, nil
}

func ValidateLocalPart(e string) (bool, error) {
	if len(e) <= 0 || len(e) > 64 {
		return false, nil
	}
	l := strings.Split(e, "")
	if l[len(l)-1] == `"` && l[0] == `"` {
		cb := len(l) - 1
		for cb >= 0 && l[cb] != "" {
			if !lpQuoteString(l, cb) {
				return false, nil
			}
			cb--
		}
	} else {
		if l[0] == "." {
			return false, nil
		}
		if l[0] == "(" {
			cc := strings.Index(strings.Join(l, ""), ")")
			if cc == -1 {
				return false, nil
			} else if cc >= 0 {
				l = l[cc:]
			}
		}
		cb := len(l) - 1
		if l[cb] == ")" {
			cc := strings.Index(strings.Join(l, ""), "()")
			if cc == -1 {
				return false, nil
			} else if cc >= 0 {
				l = l[:cc]
			}
		}
		if l[cb] == "." {
			return false, nil
		}
		for cb >= 0 && l[cb] != "" {
			if !lpByteCheck(l, cb) {
				return false, nil
			} else {
				cb--
			}
		}
	}
	return true, nil
}

func ValidateFullAddress(m string) (bool, error) {
	r, err := ValidateLocalPartOfEmail(m)
	if err != nil {
		return false, err
	}
	f, err := ValidateDomainOfEmail(m)
	if err != nil {
		return false, err
	}
	if r && f {
		return true, nil
	} else {
		return false, nil
	}
}

func lpByteCheck(r []string, slice int) bool {
	sl := r[slice]
	ns := r[slice-1]
	if sl == "." && ns == "." {
		return false
	}
	if disallowed[sl] {
		return false
	}
	return true
}

func lpQuoteString(r []string, slice int) bool {
	sl := r[slice]
	ns := r[slice-1]
	if escapeneededinquotes[sl] {
		return strings.Contains(ns, `\`)
	}
	if strings.Contains(ns, `\`) {
		return false
	}
	return true
}
