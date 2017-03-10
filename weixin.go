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
	http.HandleFunc("/wx", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if *wxToken == "" {
				log.Println("token不能为空")
				w.Write(refresh)
				return
			}
			var arg []string
			var sum string
			arg = append(arg, *wxToken)
			arg = append(arg, r.FormValue("timestamp"))
			arg = append(arg, r.FormValue("nonce"))
			sort.Strings(arg)
			for i := 0; i < len(arg); i++ {
				sum += arg[i]
			}
			log.Println(sum)
			h := sha1.New()
			if _, err := h.Write([]byte(sum)); err != nil {
				log.Println(err)
				w.Write(refresh)
			}
			if fmt.Sprintf("%x",h.Sum(nil)) != r.FormValue("signature") {
				log.Println("sha1不匹配！")
				w.Write(refresh)
				return
			}
			w.Write([]byte(r.FormValue("echostr")))
			log.Println("验证成功！")
		}
	})
	http.ListenAndServe(*host+":"+*port, nil)
}
