//go:build !windows

package migrations

import (
	"errors"
	"os"
	"syscall"
)

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func ownerFromInfo(info os.FileInfo) *fileOwner {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return &fileOwner{UID: int(stat.Uid), GID: int(stat.Gid)}
}

func setFileOwner(file *os.File, owner *fileOwner) error {
	if owner == nil {
		return nil
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if current := ownerFromInfo(info); current != nil && *current == *owner {
		return nil
	}
	return file.Chown(owner.UID, owner.GID)
}
