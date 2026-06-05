package halt

import (
	"os"
	"os/signal"
)

type Callback func(sig os.Signal)

func On(f Callback, sigs ...os.Signal) {
	c := make(chan os.Signal, 1)
	for _, sig := range sigs {
		signal.Notify(c, sig)
	}
	go watch(f, c)
}

func watch(f Callback, c <-chan os.Signal) {
	for sig := range c {
		f(sig)
	}
}
