package main

import (
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/synqronlabs/raven"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	server := raven.New("mail.example.com").
		Addr(":2525").
		Logger(logger).
		ReadTimeout(1 * time.Second).
		MaxMessageSize(10 * 1024 * 1024). // 10MB
		OnConnect(func(c *raven.Context) *raven.Response {
			logger.Info("connection", "remote", c.Connection.RemoteAddr().String())
			return c.Next()
		}).
		OnMessage(func(c *raven.Context) *raven.Response {
			logger.Info("message received",
				"from", c.Mail.Envelope.From.String(),
				"recipients", len(c.Mail.Envelope.To))
			return c.Next()
		})

	if err := server.ListenAndServe(); err != raven.ErrServerClosed {
		log.Fatal(err)
	}
}
