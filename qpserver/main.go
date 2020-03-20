package main

import (
	"crypto/tls"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/lucas-clemente/quic-go"

	"flag"

	log "github.com/liudanking/goutil/logutil"
	"github.com/liudanking/quic-proxy/common"
)

func main() {
	var (
		listenAddr string
		cert       string
		key        string
		//auth       string
		verbose bool
	)
	flag.StringVar(&listenAddr, "l", ":1246", "listen addr (udp port only)")
	flag.StringVar(&cert, "cert", "D:\\Codes\\GO\\proxy\\cert\\cert.pem", "")
	flag.StringVar(&key, "key", "D:\\Codes\\GO\\proxy\\cert\\domain.key", "")
	//flag.StringVar(&auth, "auth", "user:psw", "basic auth, format: username:password")
	flag.BoolVar(&verbose, "v", true, "verbose")
	flag.Parse()

	log.Info("%v", verbose)
	if cert == "" || key == "" {
		log.Error("cert and key can't by empty")
		return
	}

	// parts := strings.Split(auth, ":")
	// if len(parts) != 2 {
	// 	log.Error("auth param invalid")
	// 	return
	// }
	// username, password := parts[0], parts[1]

	listener, err := quic.ListenAddr(listenAddr, generateTLSConfig(cert, key), nil)
	if err != nil {
		log.Error("listen failed:%v", err)
		return
	}
	ql := common.NewQuicListener(listener)

	proxy := goproxy.NewProxyHttpServer()
	// ProxyBasicAuth(proxy, func(u, p string) bool {
	// 	return u == username && p == password
	// })
	proxy.Verbose = verbose
	server := &http.Server{Addr: listenAddr, Handler: proxy}
	log.Info("start serving %v", listenAddr)
	log.Error("serve error:%v", server.Serve(ql))

}

func generateTLSConfig(certFile, keyFile string) *tls.Config {
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{common.KQuicProxy},
	}
}
