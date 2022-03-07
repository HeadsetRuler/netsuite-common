package netsuite

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/alph4numb3r/goccm"
)

// Portsniffer
//
// ALL public functions return an array of open ports and an array of any errors encountered
type PortSniffer struct{
	delay time.Duration
	timeout time.Duration
	conc *goccm.ConcurrencyManager
}

// Creates a new portsniffer, provide nil (to use defaults) or any amount of the following key/value pairs:
//
// ---
//
// timeout time.Duration (default 0.5 seconds) : timeout for each connection
//
// maxConc int (default 50) : maximum amount of concurrent connections
//
// delay time.Duration (default 50 ms) : delay between connections
func NewPortSniffer(args map[string]interface{}) *PortSniffer {
	const (
		delayDefault time.Duration = time.Millisecond * 50
		timeoutDefault time.Duration = time.Second / 2
		maxConcDefault int = 50
	)

	p := new(PortSniffer)
	if args != nil {
		// try to use provided timeout
		timeoutIn, timeoutExists := args["timeout"]
		if timeoutExists { // is the value provided?
			timeoutTemp, valid := timeoutIn.(time.Duration)
			if valid { // is it the correct type?
				p.timeout = timeoutTemp
			} else {
				log.Println("Argument 'timeout' has invalid type, using default: ", timeoutDefault)
				p.timeout = timeoutDefault
			}
		} else {
			p.timeout = timeoutDefault
		}
		// try to use provided maximum concurrency
		maxConcIn, maxConcExists := args["maxConc"]
		if maxConcExists { // is the value provided?
			maxConcTemp, valid := maxConcIn.(int)
			if valid { // is it the correct type?
				p.conc = goccm.New(maxConcTemp)
			} else {
				log.Println("Argument 'maxConc' has invalid type, using default: ", maxConcDefault)
				p.conc = goccm.New(maxConcDefault)
			}
		} else {
			p.conc = goccm.New(maxConcDefault)
		}
		delayIn, delayExists := args["delay"]
		if delayExists { // is the value provided?
			delayTemp, valid := delayIn.(time.Duration)
			if valid { // is it the correct type?
				p.delay = delayTemp
			} else {
				log.Println("Argument 'delay' has invalid type, using default: ", delayDefault)
				p.delay = delayDefault
			}
		} else {
			p.delay = delayDefault
		}
	} else { // if args is empty, ALL DEFAULTS
		p.delay = delayDefault
		p.conc = goccm.New(maxConcDefault)
		p.timeout = timeoutDefault
	}
	return p
}

// Sniffs a single port
func (p *PortSniffer) PortSniffSingle(targethost string, port uint16) (openports []uint16, e []error) {
	//input validation time!
	if net.ParseIP(targethost) == nil {
		e = append(e, errors.New("invalid IP address:" + targethost))
		return nil, e
	}
	open, err := p.portSniff(net.JoinHostPort(targethost, fmt.Sprint(port)))
	if err != nil {
		e = append(e, err)
		return nil, e
	}
	if open {
		openports = make([]uint16,1)
		openports[0] = port
	}
	return
}

// Sniffs a range of ports (including both the start and end). 
func (p *PortSniffer) PortSniffRange(targethost string, rangeStart uint16, rangeEnd uint16) (openports []uint16, e []error) {
	//input validation time!
	if net.ParseIP(targethost) == nil {
		e = append(e, errors.New("invalid IP address:" + targethost))
		return nil, e
	}
	if rangeStart==rangeEnd{ // that's a single port buddy, but that's okay! i got you!
		log.Println("Scanning a range of size 1!")
		return p.PortSniffSingle(targethost, rangeStart)
	}
	if rangeStart>rangeEnd{ // start is after end, that's wrong, but i'm nice so i'll flip them for you
		temp := rangeEnd
		rangeEnd = rangeStart
		rangeStart = temp
		log.Println("Argument 'rangeStart' (", rangeStart, ") was bigger than 'rangeEnd' (", rangeEnd, "), flipping")
	}

	openports = make([]uint16, 0, 1+rangeEnd-rangeStart)
	responseChannels := make(map[uint16](chan struct{open bool; e error}), 1+rangeEnd-rangeStart)
	for i := rangeStart; i <= rangeEnd; i++ {
		responseChannels[i] = make(chan struct{open bool; e error},1)
		time.Sleep(p.delay)
		p.portSniffAsync(net.JoinHostPort(targethost, fmt.Sprint(i)),responseChannels[i])
	}
	p.conc.WaitAllDone()
	for i,responseChannel := range responseChannels {
		response := <-responseChannel
		if response.e != nil {
			e = append(e, response.e)
		}
		if response.open {
			openports = append(openports, uint16(i))
		}
	}
	return
}


// Sniffs a given set of ports
func (p *PortSniffer) PortSniffArray(targethost string, targetports []uint16) (openports []uint16, e []error) {
	//input validation time!
	if net.ParseIP(targethost) == nil {
		e = append(e, errors.New("invalid IP address:" + targethost))
		return nil, e
	}
	if targetports == nil {
		e = append(e, errors.New("no array to scan provided"))
		return nil, e
	}
	
	openports = make([]uint16, 0 , len(targetports))
	responseChannels := make(map[uint16](chan struct{open bool; e error}), len(targetports))
	for _,i := range targetports {
		responseChannels[i] = make(chan struct{open bool; e error},1)
		time.Sleep(p.delay)
		p.portSniffAsync(net.JoinHostPort(targethost, fmt.Sprint(i)),responseChannels[i])
	}
	p.conc.WaitAllDone()
	for i,responseChannel := range responseChannels {
		response := <-responseChannel
		if response.e != nil {
			e = append(e, response.e) 
			return
		}
		if response.open {
			openports = append(openports, uint16(i))
		}
	}
	return
	
}


//Internal function, use PortSniffSingle instead
func (p *PortSniffer) portSniff(target string) (open bool, e error) {
	conn, err := net.DialTimeout("tcp", target, p.timeout)
	if err != nil {
		if !strings.Contains(err.Error(), "timeout") {
			e = errors.New(fmt.Sprint("While scanning ", target , ":\n", err.Error()))
		}
		return
	} else {
		defer conn.Close()
		open = true
		return
	}
}

func (p *PortSniffer) portSniffAsync(target string, out chan struct{open bool; e error}) {
	p.conc.Wait()
	go func() {	
		defer p.conc.Done()
		open, e := p.portSniff(target)
		out <- struct{open bool; e error}{open,e}
	} ()
}

/* {
	e = nil
	if targetports == nil {
		targetports = 
	}

	if addrerr == nil { // port given, scan target port
		conn, err := net.Dial("tcp", targethost)
		if err != nil {
			e = err
			return
		}
		defer conn.Close()
		fport,_ := strconv.ParseUint(port,10,0)
		ports = append(ports, uint(fport))
		return
	} else if strings.Contains(addrerr.Error(), "missing port in address") { // no port given, scan every port
		conc := goccm.New(3000)
		for i := uint(1); i < 65536; i++ {
				conc.Wait()
				go func (i uint) (i)
				if e != nil {
					return
				}

		}
		conc.WaitAllDone()
		return
	} else { // some other error, pass it up the chain
		e = addrerr
		return
	}
}
*/