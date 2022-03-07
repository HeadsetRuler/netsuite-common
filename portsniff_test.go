package netsuite

import (
	"fmt"
	"testing"
)

func Test_SingleSniff(t *testing.T) {
	p := NewPortSniffer(nil)
	res,err := p.PortSniffSingle("1.1.1.1", 80)
	fmt.Println(res,err)
	if fmt.Sprint(res,err) != "[80] []" {t.Fail()}
	res,err = p.PortSniffSingle("1.1.1.1", 81)
	fmt.Println(res,err)
	if fmt.Sprint(res,err) != "[] []" {t.Fail()}
	res,err = p.PortSniffSingle("1.1.1.1", 53)
	fmt.Println(res,err)
	if fmt.Sprint(res,err) != "[53] []" {t.Fail()}
}

func Test_SniffRange(t *testing.T) {
	p := NewPortSniffer(nil)
	res,err := p.PortSniffRange("1.1.1.1",1,1000)
	fmt.Println(res,err)
	var matches int = 0
	for _,a := range res {
		if a == 53 || a == 80 || a == 443 || a == 853 {matches++}
	}
	if matches != 4 || len(err) != 0 {t.Fail()}
}

func Test_SniffArray(t *testing.T) {
	p := NewPortSniffer(nil)
	res,err := p.PortSniffArray("1.1.1.1",[]uint16{53,80,443,853})
	fmt.Println(res,err)
	var matches int = 0
	for _,a := range res {
		if a == 53 || a == 80 || a == 443 || a == 853 {matches++}
	}
	if matches != 4 || len(err) != 0 {t.Fail()}
}