//go:build linux
// +build linux

package fsnotify

import (
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"unsafe"
)

const fanEventSize = 24
const fanFileFlags = unix.FAN_MODIFY | unix.FAN_MOVE | unix.FAN_CREATE
const fanFSFlags = unix.FAN_MARK_FILESYSTEM | fanFileFlags

type fanotifyInfoHeader struct {
	infoType uint8
	pad      uint8
	Len      uint16
}

type fileHandle struct {
	handleBytes uint32
	handleType  int32
	// file handle of arbitrary length
}

type fanotifyEventFid struct {
	kernelFsidT [2]int32
	fileHandle  fileHandle
}

type fanotifyEventInfoFid struct {
	hdr      fanotifyInfoHeader
	eventFid fanotifyEventFid
}

type FileChange struct {
	FolderPath string
	ChangeType int
}

// FANWatcher watches a set of files via fanotify(7), delivering events to a channel.
type FANWatcher struct {
	Events   chan Event
	Errors   chan error
	mu       sync.Mutex // Map access
	fd       int
	poller   *fdPoller
	watches  map[string]*watch // Map of inotify watches (key: path)
	paths    map[int]string    // Map of watched paths (key: watch descriptor)
	done     chan struct{}     // Channel for sending a "quit message" to the reader goroutine
	doneResp chan struct{}     // Channel to respond to Close
}

func (w *FANWatcher) String() string {
	return "watcher.fanotify"
}

func (w *FANWatcher) isClosed() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

// Remove stops watching the named file or directory (non-recursively).
func (w *FANWatcher) Remove(name string) error {
	name = filepath.Clean(name)

	// Fetch the watch.
	w.mu.Lock()
	defer w.mu.Unlock()
	watch, ok := w.watches[name]

	// Remove it from inotify.
	if !ok {
		return fmt.Errorf("can't remove non-existent fanotify watch for: %s", name)
	}

	if err := unix.FanotifyMark(w.fd, unix.FAN_MARK_REMOVE, 0, int(watch.flags), name); err != nil {
		return err
	}

	// We successfully removed the watch if FanotifyMark doesn't return an
	// error, we need to clean up our internal state to ensure it matches
	// inotify's kernel state.
	delete(w.paths, int(watch.wd))
	delete(w.watches, name)

	return nil
}

// Close removes all watches and closes the events channel.
func (w *FANWatcher) Close() error {
	if w.isClosed() {
		return nil
	}

	// Send 'close' signal to goroutine, and set the Watcher to closed.
	close(w.done)

	// Wake up goroutine
	w.poller.wake()

	// Wait for goroutine to close
	<-w.doneResp

	return nil
}

// Add starts watching the named file or directory (non-recursively).
func (w *FANWatcher) Add(name string) error {
	var (
		cleanedName        = filepath.Clean(name)
		flags       uint32 = fanFileFlags
		errno       error
	)
	if w.isClosed() {
		return errors.New("fanotify instance already closed")
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	watchEntry := w.watches[cleanedName]
	if watchEntry == nil {
		flags |= unix.FAN_MARK_ADD
	}

	if errno = unix.FanotifyMark(w.fd, uint(flags), 0, unix.AT_FDCWD, cleanedName); errno != nil {
		return errno
	}

	if watchEntry == nil {
		w.watches[cleanedName] = &watch{wd: uint32(w.fd), flags: flags}
		w.paths[w.fd] = cleanedName
	} else {
		watchEntry.wd = uint32(w.fd)
		watchEntry.flags = flags
	}

	return nil
}

// NewFANWatcher establishes a new watcher with the underlying OS and begins waiting for events.
func NewFANWatcher() (*FANWatcher, error) {
	// Create fanotify fd
	fd, errno := unix.FanotifyInit(unix.FAN_CLASS_NOTIF, unix.IN_CLOEXEC)
	if fd == -1 {
		return nil, errno
	}

	// Create epoll
	poller, err := newFdPoller(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	w := &FANWatcher{
		fd:       fd,
		poller:   poller,
		watches:  make(map[string]*watch),
		paths:    make(map[int]string),
		Events:   make(chan Event),
		Errors:   make(chan error),
		done:     make(chan struct{}),
		doneResp: make(chan struct{}),
	}

	go w.readEvents()
	return w, nil
}

func readSingleEvent(r io.Reader) (Event, error) {
	var (
		resultEvent Event                       = Event{}
		readError                               = errors.New("could not get full packet from fanotify fd")
		fanInfo     *unix.FanotifyEventMetadata = new(unix.FanotifyEventMetadata)
	)
	metaBuffer := make([]byte, 2*unsafe.Sizeof(fanInfo))
	n, err := r.Read(metaBuffer)
	if err != nil {
		return resultEvent, err
	}

	if n < 0 || n > 24 {
		return resultEvent, readError
	}

	meta := *((*unix.FanotifyEventMetadata)(unsafe.Pointer(&metaBuffer[0])))
	bytesLeft := int(meta.Event_len - uint32(meta.Metadata_len))
	infoBuff := make([]byte, bytesLeft)
	n, err = r.Read(infoBuff)
	if err != nil {
		return resultEvent, err
	}

	if n < 0 || n > bytesLeft {
		return resultEvent, readError
	}

	info := *((*fanotifyEventInfoFid)(unsafe.Pointer(&infoBuff[0])))

	log.Printf("Received info header of type %d and total size of %d\n",
		info.hdr.infoType,
		int(meta.Event_len-uint32(meta.Metadata_len)))
	log.Printf("%s\n", string(infoBuff))

	if info.hdr.infoType != unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
		// We don't handle all events
		return resultEvent, nil
	}
	/*
			handleStart := uint32(unsafe.Sizeof(info))
			handleLen := info.eventFid.fileHandle.handleBytes
			handleBytes := infoBuff[handleStart : handleStart+handleLen]
			unixFileHandle := unix.NewFileHandle(info.eventFid.fileHandle.handleType, handleBytes)
			/*
				fd, err := unix.OpenByHandleAt(atFDCWD, unixFileHandle, 0)
				if err != nil {
					log.Println("could not call OpenByHandleAt:", err)
					return
				}

				defer func() {
					err = syscall.Close(fd)
					if err != nil {
						log.Println("warning: couldn't close file descriptor", err)
					}
				}()

				sym := fmt.Sprintf("/proc/self/fd/%d", fd)
				path := make([]byte, 200)
				pathLength, err := unix.Readlink(sym, path)

				if err != nil {
					log.Println("could not call Readlink:", err)
					return
				}
				path = path[:pathLength]

		log.Println("received event, path:", string(path),
			"flags:", maskToString(meta.Mask))
	*/
	/*
		func maskToString(mask uint64) string {
			var flags []string
			if mask&unix.IN_ACCESS > 0 {
				flags = append(flags, "FAN_ACCESS")
			}
			if mask&unix.IN_ATTRIB > 0 {
				flags = append(flags, "FAN_ATTRIB")
			}
			if mask&unix.IN_CLOSE_NOWRITE > 0 {
				flags = append(flags, "FAN_CLOSE_NOWRITE")
			}
			if mask&unix.IN_CLOSE_WRITE > 0 {
				flags = append(flags, "FAN_CLOSE_WRITE")
			}
			if mask&unix.IN_CREATE > 0 {
				flags = append(flags, "FAN_CREATE")
			}
			if mask&unix.IN_DELETE > 0 {
				flags = append(flags, "FAN_DELETE")
			}
			if mask&unix.IN_DELETE_SELF > 0 {
				flags = append(flags, "FAN_DELETE_SELF")
			}
			if mask&unix.IN_IGNORED > 0 {
				flags = append(flags, "FAN_IGNORED")
			}
			if mask&unix.IN_ISDIR > 0 {
				flags = append(flags, "FAN_ISDIR")
			}
			if mask&unix.IN_MODIFY > 0 {
				flags = append(flags, "FAN_MODIFY")
			}
			if mask&unix.IN_MOVE_SELF > 0 {
				flags = append(flags, "fanMoveSelf")
			}
			if mask&unix.IN_MOVED_FROM > 0 {
				flags = append(flags, "fanMovedFrom")
			}
			if mask&unix.IN_MOVED_TO > 0 {
				flags = append(flags, "fanMovedTo")
			}
			if mask&unix.IN_OPEN > 0 {
				flags = append(flags, "FAN_OPEN")
			}
			if mask&unix.IN_Q_OVERFLOW > 0 {
				flags = append(flags, "FAN_Q_OVERFLOW")
			}
			if mask&unix.IN_UNMOUNT > 0 {
				flags = append(flags, "FAN_UNMOUNT")
			}
			return strings.Join(flags, ", ")
		}*/
	resultEvent.Op = maskToOp(meta.Mask)

	return resultEvent, nil
}

func (w *FANWatcher) readEvents() {
	var (
		errno error // Syscall errno
		ok    bool  // For poller.wait
		evt   Event
	)

	defer close(w.doneResp)
	defer close(w.Errors)
	defer close(w.Events)
	defer unix.Close(w.fd)
	defer w.poller.close()

	f := os.NewFile(uintptr(w.fd), "")
	r := bufio.NewReader(f)

	for {
		// See if we have been closed.
		if w.isClosed() {
			return
		}

		ok, errno = w.poller.wait()
		if errno != nil {
			select {
			case w.Errors <- errno:
			case <-w.done:
				return
			}
			continue
		}

		if !ok {
			continue
		}

		if evt, errno = readSingleEvent(r); errno == nil {
			w.Events <- evt
		}
	}
}

func maskToOp(mask uint64) Op {
	var ret Op
	if mask&unix.FAN_ACCESS > 0 ||
		mask&unix.FAN_ACCESS_PERM > 0 {
		ret |= Access
	}

	if mask&unix.FAN_ATTRIB > 0 {
		ret |= Chmod
	}

	if mask&unix.FAN_CREATE > 0 {
		ret |= Create
	}
	if mask&unix.FAN_DELETE > 0 ||
		mask*unix.FAN_DELETE_SELF > 0 {
		ret |= Remove
	}
	if mask&unix.FAN_MODIFY > 0 {
		ret |= Write
	}

	if mask&unix.FAN_MOVE > 0 ||
		mask&unix.FAN_MOVED_TO > 0 ||
		mask&unix.FAN_MOVED_FROM > 0 {
		ret |= Rename
	}

	return ret
}
