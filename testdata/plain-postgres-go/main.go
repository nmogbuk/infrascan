package main

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5"
)

func main() {
	conn, err := pgx.Connect(context.Background(), "postgres://localhost:5432/app")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close(context.Background())
}
