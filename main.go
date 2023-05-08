package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	middleware2 "jwtauthentication/middleware"
	"log"
	"net/http"
	"time"
)

func main() {
	r := chi.NewRouter()

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	r.Use(middleware.Timeout(60 * time.Second))

	r.Post("/signin", SignIn)

	r.Route("/api", func(r chi.Router) {
		r.Use(middleware2.AuthenticationMiddleware)
		r.Get("/welcome", Welcome)
		r.Post("/refresh", Refresh)
		r.Post("/logout", Logout)
	})

	log.Fatal(http.ListenAndServe(":8000", r))
}
