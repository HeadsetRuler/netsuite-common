package netsuite

import (
	"fmt"
	"testing"
)

func Test_SingleSniff(t *testing.T) {
	p := NewPortSniffer(nil)
	res,err :=	p.PortSniffSingle("1.1.1.1", 80)
	fmt.Println(res,err)
}

func Test_SniffRange(t *testing.T) {
	p := NewPortSniffer(nil)
	res,err := p.PortSniffRange("1.1.1.1",1,1000)
	fmt.Println(res,err)
}