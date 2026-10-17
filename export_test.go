package routecheck

// Compiles returns how many policies Check has compiled in this process, for
// TestCheckCompilesOncePerReport (Review Focus 4). Tests that read it must
// not run in parallel with other Check calls.
func Compiles() int64 { return compiles.Load() }
