package main

import (
	"crypto/sha1"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
)

func main() {
	var wxToken = flag.String("wxtoken", "", "WeiXin Token")
	var host = flag.String("host", "127.0.0.1", "listen host")
	var port = flag.String("port", "80", "listen port")
	var refresh = []byte(`<html>
<meta http-equiv="refresh" content="0;url=https://kaiiak.github.io/">
</html>`)

	flag.Parse()
	if *wxToken == "" {
		panic("token 不能为空")
	}
	http.HandleFunc("/wx/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			var arg []string
			var sum string
			arg = append(arg, *wxToken)
			arg = append(arg, r.FormValue("timestamp"))
			arg = append(arg, r.FormValue("nonce"))
			sort.Strings(arg)
			for i := 0; i < len(arg); i++ {
				sum += arg[i]
			}
			h := sha1.New()
			if _, err := h.Write([]byte(sum)); err != nil {
				w.WriteHeader(http.StatusForbidden)
				log.Println(err)
				w.Write(refresh)
				return
			}
			if fmt.Sprintf("%x", h.Sum(nil)) != r.FormValue("signature") {
				w.WriteHeader(http.StatusUnauthorized)
				log.Println("sha1不匹配！")
				w.Write(refresh)
				return
			}
			w.Write([]byte(r.FormValue("echostr")))
			log.Printf("timestamp:%s, nonce: %s, signature:%s, echostr:%s\n", r.FormValue("timestamp"), r.FormValue("nonce"), r.FormValue("signature"), r.FormValue("echostr"))
			log.Println("验证成功！")
		}
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("404 not found")
		w.WriteHeader(http.StatusNotFound)
		w.Write(refresh)
	})
	http.ListenAndServe(*host+":"+*port, nil)
}
