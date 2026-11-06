package proxy

import (
	"io"
	"log"
)

// net/http can include client addresses or request text in diagnostics. The gateway
// exposes bounded counters and fixed error classes instead of copying those logs.
func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }
