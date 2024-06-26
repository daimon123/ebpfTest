package main

import (
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"runtime"
)

func GetNetNs(pid uint32) (netns.NsHandle, error) {
	return netns.GetFromPid(int(pid))
}

func GetSelfNetNs() (netns.NsHandle, error) {
	return netns.Get()
}

func GetHostNetNs() (netns.NsHandle, error) {
	return GetNetNs(1)
}

func SetCgroupNamespace(targetNs netns.NsHandle, selfNs netns.NsHandle) error {
	if selfNs.Equal(targetNs) {
		return nil
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Setns(int(targetNs), unix.CLONE_NEWCGROUP); err != nil {
		return err
	}

	return nil
}

// TODO Execute Cgroup 함수
