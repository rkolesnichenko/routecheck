//go:build unix

package routecheck_test

import (
	"syscall"
	"time"
)

// haveRusage is true where getrusage exists.
const haveRusage = true

// rusage returns the process's user and system CPU time so far.
func rusage() (user, sys time.Duration) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		panic(err)
	}
	return time.Duration(ru.Utime.Nano()), time.Duration(ru.Stime.Nano())
}
