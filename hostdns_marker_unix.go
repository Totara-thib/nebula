//go:build !windows

package nebula

import (
	"os"

	"golang.org/x/sys/unix"
)

// createMarkerFile creates the marker at path, failing if anything is already
// there.
func createMarkerFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
