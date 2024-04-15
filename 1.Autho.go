/*
@origin Author : idealeer
@File : Kaweh:dns_server.go
@Software: GoLand
@Time : 2022-4-26 15:04:27
*/
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device      = "ens33"
	srcMac      = net.HardwareAddr{0x00, 0x0c, 0x29, 0x5e, 0xa0, 0x6a}
	gtwMac      = net.HardwareAddr{0xdc, 0xda, 0x80, 0xd8, 0xcf, 0x81}
	srcIP       = net.ParseIP("202.112.51.96")
	srcPort     = 53
	handleSend  *pcap.Handle
	err         error
	basedomain  = "tsukingtest.dnssec.top"
	rdata       = "127.0.0.1"
	time_format = "2006-01-02 MST 15:04:05.000000"
)

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip.String()
}

func Make_Ethernet() *layers.Ethernet {
	return &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMac,
		DstMAC:       gtwMac,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}
}

func Make_IPv4(dstIP string) *layers.IPv4 {
	return &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      srcIP,
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}
}

func Make_UDP(dstPort layers.UDPPort) *layers.UDP {
	return &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPort),
		DstPort:   layers.UDPPort(dstPort),
		Length:    0,
		Checksum:  0,
	}
}

func Make_DNS(txid uint16, dns_Questions []layers.DNSQuestion, dns_Answers []layers.DNSResourceRecord, dns_Authorities []layers.DNSResourceRecord, dns_Additionals []layers.DNSResourceRecord) *layers.DNS {
	return &layers.DNS{
		BaseLayer:    layers.BaseLayer{},
		ID:           txid,
		QR:           true,
		OpCode:       0,
		AA:           true,
		TC:           false,
		RD:           false,
		RA:           false,
		Z:            0,
		ResponseCode: 0,
		QDCount:      uint16(len(dns_Questions)),
		ANCount:      uint16(len(dns_Answers)),
		NSCount:      uint16(len(dns_Authorities)),
		ARCount:      uint16(len(dns_Additionals)),
		Questions:    dns_Questions,
		Answers:      dns_Answers,
		Authorities:  dns_Authorities,
		Additionals:  dns_Additionals,
	}
}

func Simp_resp(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32,
	rdata string) {
	var log_info string
	//构建eth层
	ethernetLayer := Make_Ethernet()
	//构建IP层
	ipv4Layer := Make_IPv4(dstIP)
	//构建UDP层
	udpLayer := Make_UDP(dstPort)
	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		log.Println("Error: ", err)
		return
	}
	var dnsLayer *layers.DNS
	ttl = 10
	dns_Questions := []layers.DNSQuestion{
		{
			Name:  []byte(qname),
			Type:  qtype,
			Class: layers.DNSClassIN,
		},
	}
	dns_Answers := []layers.DNSResourceRecord{
		{
			Name:  []byte(qname),
			TTL:   ttl,
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			IP:    net.ParseIP(rdata),
		},
	}
	dnsLayer = Make_DNS(txid, dns_Questions, dns_Answers, nil, nil)
	log_info = fmt.Sprintf("%s : to %s with %s %s %d %s\n", time.Now().Format(time_format), dstIP, qname, qtype.String(), ttl, rdata)

	//构建链路管道
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(
		buffer,
		options,
		ethernetLayer,
		ipv4Layer,
		udpLayer,
		dnsLayer,
	)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	//发送response
	outgoingPacket := buffer.Bytes()
	err = handleSend.WritePacketData(outgoingPacket)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	fmt.Printf(log_info)
}

func Dealpacket(packet gopacket.Packet) {
	// 数据流管道
	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var udp layers.UDP
	var dns_ layers.DNS
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &udp, &dns_)
	//解析错误
	if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
		return
	}
	//没有查询，不做处理
	if len(dns_.Questions) <= 0 {
		return
	}
	//不包含基础域名，不做处理
	if !strings.HasSuffix(strings.ToLower(string(dns_.Questions[0].Name)), basedomain) {
		return
	}

	//请求时间
	tim := strconv.FormatInt(packet.Metadata().CaptureInfo.Timestamp.UnixMilli(), 10)
	dstIP := ipv4.SrcIP.String()
	qname := string(dns_.Questions[0].Name)
	qtype := dns_.Questions[0].Type
	txid := dns_.ID
	dstPort := udp.SrcPort
	ttl := 10
	rdata_ := rdata
	log.Printf("%s fr %s:%d, query %s\n", tim, ipv4.SrcIP.String(), udp.SrcPort, string(dns_.Questions[0].Name))

	//对于 *.rdtest.tsukingtest.dnssec.top 的查询，提取递归地址
	if strings.Contains(strings.ToLower(qname), ".rdtest.") {
		// 定义正则表达式，匹配形如 `-数字.` 的模式，其中数字为连续的十进制数
		r := regexp.MustCompile(`-(\d+)\.rdtest\.tsukingtest\.dnssec\.top`)
		matches := r.FindStringSubmatch(qname)
		if matches == nil {
			log.Println("Extra target_resolver failure: %s", qname)
			return
		}
		vul_resolver_int_string := matches[1]
		vul_resolver_int64, err := strconv.ParseUint(vul_resolver_int_string, 10, 32)
		if err != nil {
			fmt.Println("转换失败:", err)
		}
		vul_resolver_int := uint32(vul_resolver_int64)
		fmt.Println(int2ip(vul_resolver_int))
	}

	//对于 *.basetest.tsukingtest.dnssec.top 的查询，做出回复
	if strings.Contains(strings.ToLower(qname), ".basetest.") {
		Simp_resp(dstIP, dstPort, qname, qtype, txid, uint32(ttl), rdata_)
	}
}
func Simpauthor() {
	fmt.Printf("%s : %s\n", time.Now().Format(time_format), "DNS server starts")

	//发送句柄
	handleSend, err = pcap.OpenLive(device, 1024, false, 0*time.Second)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	defer handleSend.Close()

	//接收句柄
	handleRecv, err := pcap.OpenLive(device, 1024, false, time.Nanosecond)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	defer handleRecv.Close()

	//创建过滤器
	var filter = fmt.Sprintf("ip and udp dst port %d", srcPort)
	err = handleRecv.SetBPFFilter(filter)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	//接收句柄绑定
	err = handleRecv.SetDirection(pcap.DirectionIn)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	packetSource := gopacket.NewPacketSource(handleRecv, handleRecv.LinkType())
	packetChan := packetSource.Packets()

	//处理数据流
	for packet := range packetChan {
		go Dealpacket(packet)
	}
}

func main() {
	Simpauthor()
}
