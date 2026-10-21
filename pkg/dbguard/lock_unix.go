//go:build !windows

package dbguard

import (
	"os"

	"golang.org/x/sys/unix"
)

func lock(file *os.File, exclusive bool) error {
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	return unix.Flock(int(file.Fd()), mode|unix.LOCK_NB)
}

func unlock(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }
