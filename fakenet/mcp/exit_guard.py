# Copyright 2026 Google LLC
"""Nonqueued machine-wide entry ownership for the bounded exit helper."""

NAME = r'Global\FakeNetNgMcp.ExitEvidence.v1'


class SingleFlight:
    def __init__(self):
        self.handle = None
        self.owned = False

    def acquire(self):
        import pywintypes
        import win32event
        import win32security
        attributes = pywintypes.SECURITY_ATTRIBUTES()
        attributes.bInheritHandle = False
        attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            'D:P(A;;GA;;;SY)(A;;GA;;;BA)', 1)
        self.handle = win32event.CreateMutex(attributes, False, NAME)
        result = win32event.WaitForSingleObject(self.handle, 0)
        self.owned = result in (win32event.WAIT_OBJECT_0, win32event.WAIT_ABANDONED)
        if not self.owned:
            self.close()
        return self.owned

    def close(self):
        import win32event
        if self.handle is not None:
            if self.owned:
                win32event.ReleaseMutex(self.handle)
                self.owned = False
            self.handle.Close()
            self.handle = None

    def __enter__(self):
        if not self.acquire():
            raise RuntimeError('exit evidence helper active')
        return self

    def __exit__(self, *exc):
        self.close()
