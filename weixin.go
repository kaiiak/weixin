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
	var refreshURL = `https://kaiiak.github.io/`

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
				http.Redirect(w, r, refreshURL, http.StatusFound)
				return
			}
			if fmt.Sprintf("%x", h.Sum(nil)) != r.FormValue("signature") {
				w.WriteHeader(http.StatusUnauthorized)
				log.Println("sha1不匹配！")
				http.Redirect(w, r, refreshURL, http.StatusFound)
				return
			}
			w.Write([]byte(r.FormValue("echostr")))
			log.Println("验证成功！")
			return
		}
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("404 not found: ", r.URL)
		w.WriteHeader(http.StatusNotFound)
		http.Redirect(w, r, refreshURL, http.StatusFound)
	})
	http.ListenAndServe(*host+":"+*port, nil)
}
