use sysinfo::Pid;

use darwin_libproc_sys::proc_fdinfo;

pub fn get_wine_env(pid: Pid) -> (String, String) {
    // On mac:
    // For some reason, only the wineserver has environment variables we can access, so we need to find it instead
    // Get open fd's of target, search for /private/tmp/.wine-(UID)/server-*/*,
    // using http://blog.palominolabs.com/2012/06/19/getting-the-files-being-used-by-a-process-on-mac-os-x/
    // Get directory of that file,
    // Find wineserver with matching CWD by searching for a process with that cwd
    // (no others use that cwd I believe, though should assert that basename of exe == 'wineserver')
    // Use the env and path of that wineserver process to find WINEPREFIX and binary
    unsafe {
        let fdinfos: Vec<proc_fdinfo> = Vec::with_capacity(1);
    }

    todo!()
}
