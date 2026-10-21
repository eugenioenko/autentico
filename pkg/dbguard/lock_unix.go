//go:build !windows

package dbguard

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// Keep the inode stable: unlinking a lock would let another process acquire a
// different inode while this one is still held. Privileged upgrades give the
// lock the database's ownership so the service can reopen it afterwards.
func prepareLock(file *os.File, path string) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || stat.Nlink != 1 {
		return fmt.Errorf("lock must be a regular file with a single link")
	}
	if os.Geteuid() != 0 {
		return nil
	}
	database, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	owner := database.Sys().(*syscall.Stat_t)
	if err := file.Chown(int(owner.Uid), int(owner.Gid)); err != nil {
		return err
	}
	return file.Chmod(database.Mode().Perm() & 0660)
}

func lock(file *os.File, exclusive bool) error {
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	return unix.Flock(int(file.Fd()), mode|unix.LOCK_NB)
}

func unlock(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }
