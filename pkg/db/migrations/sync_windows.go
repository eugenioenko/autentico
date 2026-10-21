package migrations

import "os"

// Windows does not support fsync on directory handles. File contents are synced
// before close; recovery records are retained until replacement has completed.
func syncDirectory(string) error { return nil }

func ownerFromInfo(os.FileInfo) *fileOwner    { return nil }
func setFileOwner(*os.File, *fileOwner) error { return nil }
