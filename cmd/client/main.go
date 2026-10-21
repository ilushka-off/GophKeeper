// Command client is the GophKeeper command-line client.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/ilushka-off/GophKeeper/internal/client/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Execute(ctx, cli.Env{}, os.Args[1:])
	stop()
	os.Exit(code)
}
