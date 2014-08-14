package domains

import (
	"fmt"
	"io/ioutil"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// A Checker checks if a domain is available.
type Checker interface {
	IsTaken(domain string) bool
}

type CheckerFunc func(domain string) bool

func (c CheckerFunc) IsTaken(domain string) bool {
	return c(domain)
}

type WhoisChecker struct {
	servers []string
}

func NewWhoisChecker(servers []string) *WhoisChecker {
	return &WhoisChecker{servers}
}

const (
	// any more than this means it's probably a valid whois and unavailable.
	isTakenThreshold = 3000
	// if whois has this text it is unavailable
	notFoundText = "No match"
)

func (w *WhoisChecker) WhoisAny(domain string) []byte {
	found := make(chan []byte)

	find := func(i int) {
		res, err := Whois(domain, w.servers[i])
		if err != nil {
			return
		}

		if len(res) > isTakenThreshold && !strings.Contains(string(res), notFoundText) {
			found <- res
		}
	}
	for i := range w.servers {
		go find(i)
	}
	select {
	case res := <-found:
		return res
	case <-time.After(1 * time.Second):
		return nil
	}
}

func (w *WhoisChecker) IsTaken(domain string) bool {
	return len(w.WhoisAny(domain)) > 0
}

func (w *WhoisChecker) printRespondingServers() {
	var wg sync.WaitGroup
	wg.Add(len(w.servers))
	checkServer := func(i int) {
		defer wg.Done()
		res := make(chan bool)
		go func(i int) {
			_, err := Whois("hello.com", w.servers[i])
			if err == nil {
				res <- true
			}
		}(i)
		select {
		case <-res:
			fmt.Printf("\"%s\",\n", w.servers[i])
		case <-time.After(10 * time.Second):
			return
		}
	}
	for i := range w.servers {
		go checkServer(i)
	}
	wg.Wait()
}

const whoisTimeout = 1 * time.Second

func Whois(domain, server string) ([]byte, error) {
	conn, err := net.Dial("tcp", server+":43")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(domain + "\r\n"))
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(conn)
}

func WhoisAny(domain string) []byte {
	return DefaultWhois.WhoisAny(domain)
}

func NSLookup(domain string) ([]byte, error) {
	cmd := exec.Command("nslookup", domain)
	return cmd.CombinedOutput()
}

func NSLookupChecker(domain string) bool {
	res, err := NSLookup(domain)
	if err != nil {
		return false
	}
	return strings.Contains(string(res), "Non-authoritative answer")
}

type MultiChecker struct {
	checkers []Checker
}

func (m *MultiChecker) IsTaken(domain string) bool {
	for _, checker := range m.checkers {
		if checker.IsTaken(domain) {
			return true
		}
	}
	return false
}

func (m *MultiChecker) Checker(c Checker) {
	m.checkers = append(m.checkers, c)
}

func (m *MultiChecker) CheckerFunc(fn func(domain string) bool) {
	m.checkers = append(m.checkers, CheckerFunc(fn))
}

func NewChecker() Checker {
	m := &MultiChecker{}
	m.CheckerFunc(NSLookupChecker)
	m.Checker(DefaultWhois)
	return m
}

var DefaultWhois = NewWhoisChecker(DefaultServers)
var DefaultServers = []string{
	"whois.findyouaname.com",
	"whois.godomaingo.com",
	"whois.finduaname.com",
	"whois.namestrategies.com",
	"whois.nameshere.com",
	"whois.evonames.com",
	"whois.noticeddomains.com",
	"whois.fabulous.com",
	"whois.tradenamed.com",
	"whois.heavydomains.net",
	"whois.namearsenal.com",
	"whois.namevolcano.com",
	"whois.gatekeeperdomains.net",
	"whois.goserveyourdomain.com",
	"whois.namesalacarte.com",
	"whois.lakeodomains.com",
	"whois.namesystem.com",
	"whois.netdorm.com",
	"whois.domainraker.net",
	"whois.enomtoo.com",
	"whois.enomnz.com",
	"whois.enomworld.com",
	"whois.enomten.com",
	"whois.enomx.com",
	"whois.domainclub.com",
	"whois.dyndns.com",
	"whois.namesilo.com",
	"whois.namethread.com",
	"whois.namenelly.com",
	"whois.fushitarazu.com",
	"whois.sssasss.com",
	"whois.enom423.com",
	"whois.exai.com",
	"whois.enom431.com",
	"whois.gochinadomains.com",
	"whois.initialesonline.net",
	"whois.namestream.com",
	"whois.ownidentity.com",
	"whois.nictrade.se",
	"whois.nominate.net",
	"whois.net-chinese.com.tw",
	"whois.gandi.net",
	"whois.star-domain.jp",
	"whois.subreg.cz",
	"whois.namesay.com",
	"whois.maprilis.com.vn",
	"whois.gofrancedomains.com",
	"whois.paknic.com",
	"whois.ssandomain.com",
	"whois.omnis.com",
	"whois.netim.com",
	"whois.eurotrashnames.com",
	"whois.networking4all.com",
	"whois.ipmirror.com",
	"whois.nawang.cn",
	"whois.iisp.com",
	"whois.domaindelights.com",
	"whois.nameturn.com",
	"whois.domainarmada.com",
	"whois.gradeadomainnames.com",
	"whois.domaincentre.ca",
	"whois.hawthornedomains.com",
	"whois.domaincomesaround.com",
	"whois.domaininthebasket.com",
	"whois.domaincapitan.com",
	"whois.domaingazelle.com",
	"whois.gungagalunga.biz",
	"whois.planetdomain.com",
	"whois.nayana.com",
	"whois.net4domains.com",
	"whois.ksdom.kr",
	"whois.softlayer.com",
	"whois.getyername.com",
	"whois.oldtowndomains.com",
	"whois.oregonurls.com",
	"whois.ibi.net",
	"whois.insanenames.com",
	"whois.domainprime.com",
	"whois.worthydomains.com",
	"whois.jetpackdomains.com",
	"whois.webmasters.com",
	"whois.domainsofvalue.com",
	"whois.nerdnames.com",
	"whois.enom421.com",
	"whois.worldbizdomains.com",
	"whois.netart-registrar.com",
	"whois.networksolutions.com",
	"whois.notsofamousnames.com",
	"whois.oldworldaliases.com",
	"whois.godaddy.com",
	"whois.name.com",
	"whois.nic.ru",
	"whois.onlinenic.com",
	"whois.dynanames.com",
	"whois.myobnet.com",
	"whois.22.cn",
	"whois.35.com",
	"whois.oregoneu.com",
	"whois.625domains.com",
	"whois.eNom415.com",
	"whois.enom429.com",
	"whois.hostway.com",
	"whois.pairnic.com",
	"whois.ourdomains.com",
	"whois.2imagen.net",
}
