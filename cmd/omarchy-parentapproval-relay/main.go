package main

import (
	"log"
	"os"

	"omarchy-parentapproval/internal/protocol"
	"omarchy-parentapproval/internal/relay"
	"omarchy-parentapproval/web"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	public := os.Getenv("RELAY_PUBLIC_URL")
	if public == "" {
		public = os.Getenv("PUBLIC_URL")
	}
	if public == "" {
		public = protocol.DefaultRelayURL
	}
	data := os.Getenv("RELAY_DATA")
	if data == "" {
		data = "/data"
	}

	s, err := relay.New(relay.Config{
		PublicURL: public,
		DataDir:   data,
		Web:       web.FS,
	})
	if err != nil {
		log.Fatal(err)
	}
	addr := "0.0.0.0:" + port
	if err := s.ListenAndServe(addr); err != nil {
		log.Fatal(err)
	}
}
