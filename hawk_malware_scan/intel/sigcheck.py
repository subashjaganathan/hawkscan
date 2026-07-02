"""Authenticode signature verification (Windows, via ctypes).

Verifies a file's digital signature using WinVerifyTrust for embedded
signatures and the catalog APIs for catalog-signed system binaries. Returns one
of: "valid", "invalid", "unsigned", or "unknown" (non-Windows / error).

Pure ctypes, no third-party dependency. On non-Windows platforms it returns
("unknown", ...) so callers degrade gracefully.
"""

from __future__ import annotations

import os

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    class _GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class _WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p)]

    class _WINTRUST_CATALOG_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("dwCatalogVersion", wintypes.DWORD),
                    ("pcwszCatalogFilePath", wintypes.LPCWSTR),
                    ("pcwszMemberTag", wintypes.LPCWSTR),
                    ("pcwszMemberFilePath", wintypes.LPCWSTR),
                    ("hMemberFile", wintypes.HANDLE),
                    ("pbCalculatedFileHash", ctypes.c_void_p),
                    ("cbCalculatedFileHash", wintypes.DWORD),
                    ("pcCatalogContext", ctypes.c_void_p),
                    ("hCatAdmin", wintypes.HANDLE)]

    class _WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD),
                    ("dwUnionChoice", wintypes.DWORD),
                    ("pUnion", ctypes.c_void_p),
                    ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE),
                    ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD),
                    ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    # Declare prototypes so 64-bit handles/pointers are not truncated to int.
    _wt = ctypes.windll.wintrust
    _k32 = ctypes.windll.kernel32
    _PUBYTE = ctypes.POINTER(ctypes.c_ubyte)
    _PHANDLE = ctypes.POINTER(wintypes.HANDLE)
    _PDWORD = ctypes.POINTER(wintypes.DWORD)
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.HANDLE]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _wt.WinVerifyTrust.restype = wintypes.LONG
    _wt.WinVerifyTrust.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p]
    _wt.CryptCATAdminAcquireContext.restype = wintypes.BOOL
    _wt.CryptCATAdminAcquireContext.argtypes = [_PHANDLE, ctypes.c_void_p, wintypes.DWORD]
    _wt.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL
    _wt.CryptCATAdminCalcHashFromFileHandle.argtypes = [wintypes.HANDLE, _PDWORD,
                                                        _PUBYTE, wintypes.DWORD]
    _wt.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
    _wt.CryptCATAdminEnumCatalogFromHash.argtypes = [wintypes.HANDLE, _PUBYTE,
                                                     wintypes.DWORD, wintypes.DWORD,
                                                     _PHANDLE]
    _wt.CryptCATAdminReleaseCatalogContext.argtypes = [wintypes.HANDLE,
                                                       wintypes.HANDLE, wintypes.DWORD]
    _wt.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]

    _ACTION = _GUID(0xAAC56B, 0xCD44, 0x11D0,
                    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    _TRUST_E_NOSIGNATURE = 0x800B0100
    _TRUST_E_BAD_DIGEST = 0x80096010
    _CERT_E_REVOKED = 0x800B010C

    def _verdict_from_code(code: int) -> tuple[str, str]:
        code &= 0xFFFFFFFF
        if code == 0:
            return "valid", "Authenticode signature is valid."
        if code == _TRUST_E_NOSIGNATURE:
            return "unsigned", "No valid signature found."
        if code == _TRUST_E_BAD_DIGEST:
            return "invalid", "Signature present but the file has been tampered."
        if code == _CERT_E_REVOKED:
            return "invalid", "Signing certificate is revoked."
        return "invalid", f"Signature did not verify (0x{code:08x})."

    def _verify_embedded(path: str) -> tuple[str, str]:
        fi = _WINTRUST_FILE_INFO(ctypes.sizeof(_WINTRUST_FILE_INFO), path, None, None)
        wd = _WINTRUST_DATA()
        wd.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
        wd.dwUIChoice = 2          # WTD_UI_NONE
        wd.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
        wd.dwUnionChoice = 1       # WTD_CHOICE_FILE
        wd.pUnion = ctypes.cast(ctypes.pointer(fi), ctypes.c_void_p)
        wd.dwStateAction = 1       # WTD_STATEACTION_VERIFY
        wt = ctypes.windll.wintrust
        rc = wt.WinVerifyTrust(None, ctypes.byref(_ACTION), ctypes.byref(wd))
        wd.dwStateAction = 2       # WTD_STATEACTION_CLOSE
        wt.WinVerifyTrust(None, ctypes.byref(_ACTION), ctypes.byref(wd))
        return _verdict_from_code(rc)

    def _verify_catalog(path: str) -> tuple[str, str] | None:
        """Best-effort catalog verification for system-signed binaries."""
        GENERIC_READ = 0x80000000
        OPEN_EXISTING = 3
        INVALID = wintypes.HANDLE(-1).value
        h = _k32.CreateFileW(path, GENERIC_READ, 1, None, OPEN_EXISTING, 0, None)
        if not h or h == INVALID:
            return None
        try:
            h_cat_admin = wintypes.HANDLE()
            if not _wt.CryptCATAdminAcquireContext(ctypes.byref(h_cat_admin), None, 0):
                return None
            try:
                size = wintypes.DWORD(0)
                _wt.CryptCATAdminCalcHashFromFileHandle(h, ctypes.byref(size), None, 0)
                if size.value == 0:
                    return None
                buf = (ctypes.c_ubyte * size.value)()
                if not _wt.CryptCATAdminCalcHashFromFileHandle(h, ctypes.byref(size), buf, 0):
                    return None
                h_cat = _wt.CryptCATAdminEnumCatalogFromHash(
                    h_cat_admin, buf, size.value, 0, None)
                if not h_cat:
                    return None  # not catalog-signed
                _wt.CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat, 0)
                return "valid", "Validly catalog-signed (system catalog)."
            finally:
                _wt.CryptCATAdminReleaseContext(h_cat_admin, 0)
        finally:
            _k32.CloseHandle(h)

    def verify(path: str) -> tuple[str, str]:
        try:
            status, detail = _verify_embedded(str(path))
            if status == "unsigned":
                cat = _verify_catalog(str(path))
                if cat:
                    return cat
            return status, detail
        except Exception as exc:  # never let signature checking break a scan
            return "unknown", f"verification error: {exc}"

else:  # non-Windows
    def verify(path: str) -> tuple[str, str]:
        return "unknown", "signature verification only available on Windows"
