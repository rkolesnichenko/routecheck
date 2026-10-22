//go:build !unix

package routecheck_test

import "time"

// haveRusage is false where there is no getrusage.
const haveRusage = false

// rusage returns 0, 0: there is no getrusage here, so the CPU: lines read 0
// user and 0 sys.
func rusage() (user, sys time.Duration) { return 0, 0 }
