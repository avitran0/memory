use std::fs::{read_dir, read_link, read_to_string};

pub(crate) fn find_pid(func: impl Fn(&str, &str) -> bool) -> Option<i32> {
    let Ok(read_dir) = read_dir("/proc") else {
        return None;
    };
    for process in read_dir {
        let Ok(process) = process else {
            continue;
        };

        let Ok(file_type) = process.file_type() else {
            continue;
        };

        if !file_type.is_dir() {
            continue;
        }

        let file_name = process.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };

        if !file_name.chars().all(char::is_numeric) {
            continue;
        }

        let Ok(exe_path) = read_link(process.path().join("exe")) else {
            continue;
        };

        let Some(exe_name) = exe_path.file_name() else {
            continue;
        };
        let Some(exe_name) = exe_name.to_str() else {
            continue;
        };

        let Ok(cmdline) = read_to_string(process.path().join("cmdline")) else {
            continue;
        };

        if func(exe_name, &cmdline) {
            let Ok(pid) = file_name.parse() else {
                continue;
            };
            return Some(pid);
        }
    }

    None
}

#[cfg(test)]
mod test {
    use crate::proc::find_pid;

    #[test]
    fn test_pid_self() {
        let exe = std::env::current_exe().unwrap();
        let exe_name = exe.file_name().unwrap();
        let exe_name = exe_name.to_str().unwrap();

        let found_pid = find_pid(|exe, _| exe == exe_name);
        assert!(found_pid.is_some());
        assert_eq!(std::process::id() as i32, found_pid.unwrap());
    }
}
