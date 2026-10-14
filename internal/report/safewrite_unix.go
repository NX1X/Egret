//go:build unix

package report

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Egret writes its reports as root, but in block mode the build it monitors runs
// as an ordinary user who may own parts of the output path and of the GitHub job
// summary path. If root followed a symlink that the build planted, the build
// could steer root's writes onto any file on the host (for example
// /etc/ld.so.preload). Everything here therefore resolves paths one component at
// a time and writes relative to an open directory handle, never through a path
// string that could change underneath it.

// openDirNoFollow opens dir one path component at a time. A symlink is followed
// only when the directory that holds it is owned by root and is not writable by
// group or others: only root can have planted it there, so it is part of the
// host layout (for example /home pointing at a data disk). A symlink in any
// directory a non-root user can write is refused, because the build may have
// planted it. When create is true, missing components are created with 0755.
func openDirNoFollow(dir string, create bool) (*os.File, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening /: %w", err)
	}
	for _, name := range strings.Split(strings.TrimPrefix(filepath.Clean(abs), "/"), "/") {
		if name == "" {
			continue
		}
		next, err := openDirComponent(fd, name, create)
		unix.Close(fd)
		if err != nil {
			return nil, fmt.Errorf("report path %q: %w", dir, err)
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), abs), nil
}

const dirFlags = unix.O_DIRECTORY | unix.O_RDONLY | unix.O_CLOEXEC

// openDirComponent opens one component below the directory parent.
func openDirComponent(parent int, name string, create bool) (int, error) {
	fd, err := unix.Openat(parent, name, dirFlags|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) && create {
		if merr := unix.Mkdirat(parent, name, 0o755); merr != nil && !errors.Is(merr, unix.EEXIST) {
			return -1, fmt.Errorf("creating %q: %w", name, merr)
		}
		fd, err = unix.Openat(parent, name, dirFlags|unix.O_NOFOLLOW, 0)
	}
	if err == nil {
		return fd, nil
	}
	if !errors.Is(err, unix.ELOOP) && !errors.Is(err, unix.ENOTDIR) {
		return -1, fmt.Errorf("opening %q: %w", name, err)
	}
	// name is a symlink (or not a directory). Follow it only if root alone
	// controls the directory that holds it.
	var st unix.Stat_t
	if serr := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); serr != nil || uint32(st.Mode)&unix.S_IFMT != unix.S_IFLNK {
		return -1, fmt.Errorf("%q is not a directory", name)
	}
	if !rootOnlyDir(parent) {
		return -1, fmt.Errorf("%q is a symlink in a directory a non-root user can write; refusing to follow it", name)
	}
	// Known limitation: the kernel resolves the whole target of this root-placed
	// symlink, including any user-writable directories on the way. Only the
	// directory holding the link is vouched for. Exploiting this needs root to
	// have pointed a symlink into user-writable space; components after it are
	// walked with O_NOFOLLOW again. rootOnlyDir also ignores POSIX ACLs.
	return unix.Openat(parent, name, dirFlags, 0)
}

// rootOnlyDir reports whether the open directory fd is owned by root and not
// writable by group or others.
func rootOnlyDir(fd int) bool {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false
	}
	return st.Uid == 0 && uint32(st.Mode)&0o022 == 0
}

// writeFileAt writes data to a fresh temp file inside dir and renames it onto
// name, all relative to the dir handle. The rename is atomic, so a reader never
// sees a half-written report, and it replaces a planted symlink at name instead
// of writing through it. If the build planted a DIRECTORY at name, the rename
// fails and the error is returned: the caller must not report success.
func writeFileAt(dir *os.File, name string, data []byte, perm os.FileMode) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := ".egret-report-" + hex.EncodeToString(rnd[:])
	dfd := int(dir.Fd())
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	renamed := false
	defer func() {
		if !renamed {
			_ = unix.Unlinkat(dfd, tmp, 0)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(dfd, tmp, dfd, name); err != nil {
		return fmt.Errorf("replacing %q: %w", name, err)
	}
	renamed = true
	return nil
}

// appendJobSummary appends md to $GITHUB_STEP_SUMMARY when set (a no-op off CI).
// The summary file sits in a directory the runner user owns, so it is opened
// without following symlinks and is checked before anything is written.
func appendJobSummary(md string) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return nil
	}
	dir, err := openDirNoFollow(filepath.Dir(path), false)
	if err != nil {
		return err
	}
	defer dir.Close()
	base := filepath.Base(path)
	dfd := int(dir.Fd())

	// O_NONBLOCK: a FIFO planted at the summary path would otherwise block this
	// open forever (the build is already dead, so no reader exists) and hang the
	// job. Non-blocking, it fails at once. It has no effect on a regular file.
	const flags = unix.O_WRONLY | unix.O_APPEND | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	created := false
	fd, err := unix.Openat(dfd, base, flags, 0)
	if errors.Is(err, unix.ENOENT) {
		fd, err = unix.Openat(dfd, base, flags|unix.O_CREAT|unix.O_EXCL, 0o644)
		created = err == nil
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return fmt.Errorf("job summary %q is a symlink; refusing to write through it", path)
		}
		return fmt.Errorf("opening job summary: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if !created {
		if err := checkSummaryFile(f, dfd); err != nil {
			return fmt.Errorf("job summary %q: %w", path, err)
		}
	}
	_, err = f.WriteString(md + "\n")
	return err
}

// checkSummaryFile refuses a job-summary file that is not a regular file with
// exactly one link, or whose owner is not an expected one. A second link means
// the name may be a hard link to a file the build must not reach.
func checkSummaryFile(f *os.File, parent int) error {
	var st, pst unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG {
		return errors.New("not a regular file; refusing to write")
	}
	if uint64(st.Nlink) != 1 {
		return fmt.Errorf("has %d hard links; refusing to write", st.Nlink)
	}
	if err := unix.Fstat(parent, &pst); err != nil {
		return err
	}
	if !summaryOwnerAllowed(st.Uid, pst.Uid, sudoUID(), uint32(os.Geteuid())) {
		return fmt.Errorf("owned by uid %d, which is not the invoking user, root, or the owner of its directory; refusing to write", st.Uid)
	}
	return nil
}

// summaryOwnerAllowed accepts the summary file's owner when it is the user who
// started Egret through sudo, Egret's own effective user, or the owner of the
// directory that holds the file. The last case covers container jobs and rootful
// runs without sudo, where the runner (a different uid) owns its file-commands
// directory. None of these lets the build reach a foreign file: it cannot follow
// a symlink (O_NOFOLLOW), cannot use a hard link (one link only), and a non-root
// build cannot create a file owned by anyone else.
func summaryOwnerAllowed(owner, dirOwner uint32, sudo *uint32, euid uint32) bool {
	if sudo != nil && owner == *sudo {
		return true
	}
	return owner == euid || owner == dirOwner
}

// sudoUID is SUDO_UID when Egret runs under sudo, otherwise nil.
func sudoUID() *uint32 {
	s := os.Getenv("SUDO_UID")
	if s == "" {
		return nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil
	}
	u := uint32(n)
	return &u
}
