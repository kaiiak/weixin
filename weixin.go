package main

import (
	"crypto/sha1"
	"flag"
	"log"
	"net/http"
	"sort"
)

func main() {
	var wxToken = flag.String("wxtoken", "", "WeiXin Token")
	var refresh = []byte(`<html>
<meta http-equiv="refresh" content="0;url=https://kaiiak.github.io/">
</html>`)

	flag.Parse()
	http.HandleFunc("/wx", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if *wxToken == "" {
				log.Println("token不能为空")
				w.Write(refresh)
			}
			var arg []string
			var sum string
			arg = append(arg, r.FormValue("token"))
			arg = append(arg, r.FormValue("timestamp"))
			arg = append(arg, r.FormValue("nonce"))
			sort.Strings(arg)
			for i := 0; i < len(arg); i++ {
				sum += arg[i]
			}
			h := sha1.New()
			if _, err := h.Write([]byte(sum)); err != nil {
				log.Println(err)
				w.Write(refresh)
			}
			if string(h.Sum(nil)) != r.FormValue("signature") {
				log.Println("sha1不匹配！")
				w.Write(refresh)
			}
			w.Write([]byte(r.FormValue("echostr")))
			log.Println("验证成功！")
		}
	})
	http.ListenAndServe("0.0.0.0:80", nil)
}
