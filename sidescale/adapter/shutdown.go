package adapter

import "errors"

// ErrShuttingDown is returned by work that races the shutdown drain.
var ErrShuttingDown = errors.New("shutting down")
