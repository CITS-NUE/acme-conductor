//go:build unix

package fakelego

import (
	"os"
	"os/signal"
	"syscall"
)

func ignoreTerm() {
	signal.Ignore(syscall.SIGTERM, syscall.SIGINT)
	_ = os.Getpid()
}
