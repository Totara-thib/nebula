package nebula

import (
	"os"

	"golang.org/x/sys/windows"
)

// createMarkerFile creates the marker at path, failing if anything is already
// there. CREATE_NEW refuses an existing path, and FILE_FLAG_OPEN_REPARSE_POINT
// keeps a symlink or junction planted there from being followed to its
// target, as dnsconfig's host lock open does. The error satisfies
// errors.Is(err, os.ErrExist) when the path was taken.
func createMarkerFile(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
