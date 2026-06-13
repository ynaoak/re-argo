use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct KnownFunctionSignature {
    pub name: String,
    pub return_type: String,
    pub params: Vec<(String, String)>,
    pub header: String,
    pub no_return: bool,
}

#[derive(Debug, Default)]
pub struct KnownSignatureDatabase {
    by_name: BTreeMap<String, KnownFunctionSignature>,
}

impl KnownSignatureDatabase {
    pub fn new() -> Self {
        let mut db = Self::default();
        db.load_posix();
        db.load_win32();
        db
    }

    fn load_posix(&mut self) {
        let sigs = [
            ("open", "int", &[("path", "const char*"), ("flags", "int")][..], "fcntl.h", false),
            ("close", "int", &[("fd", "int")], "unistd.h", false),
            ("read", "ssize_t", &[("fd", "int"), ("buf", "void*"), ("count", "size_t")], "unistd.h", false),
            ("write", "ssize_t", &[("fd", "int"), ("buf", "const void*"), ("count", "size_t")], "unistd.h", false),
            ("mmap", "void*", &[("addr", "void*"), ("len", "size_t"), ("prot", "int"), ("flags", "int"), ("fd", "int"), ("off", "off_t")], "sys/mman.h", false),
            ("munmap", "int", &[("addr", "void*"), ("len", "size_t")], "sys/mman.h", false),
            ("fork", "pid_t", &[], "unistd.h", false),
            ("execve", "int", &[("path", "const char*"), ("argv", "char*const*"), ("envp", "char*const*")], "unistd.h", false),
            ("_exit", "void", &[("status", "int")], "unistd.h", true),
            ("pthread_create", "int", &[("thread", "pthread_t*"), ("attr", "const pthread_attr_t*"), ("fn", "void*(*)(void*)"), ("arg", "void*")], "pthread.h", false),
        ];
        for (name, ret, params, header, no_ret) in &sigs {
            self.by_name.insert(name.to_string(), KnownFunctionSignature {
                name: name.to_string(),
                return_type: ret.to_string(),
                params: params.iter().map(|(n, t)| (n.to_string(), t.to_string())).collect(),
                header: header.to_string(),
                no_return: *no_ret,
            });
        }
    }

    fn load_win32(&mut self) {
        let sigs = [
            ("CreateFileW", "HANDLE", &[("name", "LPCWSTR"), ("access", "DWORD"), ("share", "DWORD"), ("sa", "LPSECURITY_ATTRIBUTES"), ("disp", "DWORD"), ("flags", "DWORD"), ("template", "HANDLE")][..], "windows.h", false),
            ("CloseHandle", "BOOL", &[("handle", "HANDLE")], "windows.h", false),
            ("ReadFile", "BOOL", &[("file", "HANDLE"), ("buf", "LPVOID"), ("size", "DWORD"), ("read", "LPDWORD"), ("overlapped", "LPOVERLAPPED")], "windows.h", false),
            ("WriteFile", "BOOL", &[("file", "HANDLE"), ("buf", "LPCVOID"), ("size", "DWORD"), ("written", "LPDWORD"), ("overlapped", "LPOVERLAPPED")], "windows.h", false),
            ("VirtualAlloc", "LPVOID", &[("addr", "LPVOID"), ("size", "SIZE_T"), ("type", "DWORD"), ("prot", "DWORD")], "windows.h", false),
            ("VirtualFree", "BOOL", &[("addr", "LPVOID"), ("size", "SIZE_T"), ("type", "DWORD")], "windows.h", false),
            ("GetProcAddress", "FARPROC", &[("module", "HMODULE"), ("name", "LPCSTR")], "windows.h", false),
            ("LoadLibraryA", "HMODULE", &[("name", "LPCSTR")], "windows.h", false),
            ("ExitProcess", "void", &[("code", "UINT")], "windows.h", true),
            ("GetLastError", "DWORD", &[], "windows.h", false),
        ];
        for (name, ret, params, header, no_ret) in &sigs {
            self.by_name.insert(name.to_string(), KnownFunctionSignature {
                name: name.to_string(),
                return_type: ret.to_string(),
                params: params.iter().map(|(n, t)| (n.to_string(), t.to_string())).collect(),
                header: header.to_string(),
                no_return: *no_ret,
            });
        }
    }

    pub fn lookup(&self, name: &str) -> Option<&KnownFunctionSignature> {
        let clean = name.strip_suffix("@plt").unwrap_or(name);
        self.by_name.get(clean)
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_sigs() {
        let db = KnownSignatureDatabase::new();
        let open = db.lookup("open").unwrap();
        assert_eq!(open.return_type, "int");
        assert_eq!(open.params.len(), 2);
    }

    #[test]
    fn win32_sigs() {
        let db = KnownSignatureDatabase::new();
        let create = db.lookup("CreateFileW").unwrap();
        assert_eq!(create.params.len(), 7);
        let exit = db.lookup("ExitProcess").unwrap();
        assert!(exit.no_return);
    }

    #[test]
    fn plt_strip() {
        let db = KnownSignatureDatabase::new();
        assert!(db.lookup("open@plt").is_some());
    }

    #[test]
    fn sig_count() {
        let db = KnownSignatureDatabase::new();
        assert!(db.len() >= 20);
    }
}
