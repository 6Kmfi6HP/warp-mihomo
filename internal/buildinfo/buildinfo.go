package buildinfo

import "fmt"

// Version, Revision, and Created are overridden with -ldflags -X.
var (
	Version  = "dev"
	Revision = "unknown"
	Created  = "unknown"
)

func Text() string {
	return fmt.Sprintf("warp-mihomo %s\nrevision %s\nbuilt %s\n", Version, Revision, Created)
}
