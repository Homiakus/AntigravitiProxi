//go:build windows

package atomicfile

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	moveFileExProc = kernel32.NewProc("MoveFileExW")
)

func replaceFile(oldPath, newPath string) error {
	oldp, err := syscall.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newp, err := syscall.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	r1, _, callErr := moveFileExProc.Call(
		uintptr(unsafe.Pointer(oldp)),
		uintptr(unsafe.Pointer(newp)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if r1 == 0 {
		return fmt.Errorf("MoveFileExW: %w", callErr)
	}
	return nil
}

func syncDirectory(string) error {
	// MOVEFILE_WRITE_THROUGH asks Windows to flush the move to disk before the
	// call returns. Windows does not expose a portable directory fsync through
	// the Go os package, so there is no extra directory operation here.
	return nil
}
