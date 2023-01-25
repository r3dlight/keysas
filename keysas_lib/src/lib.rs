use anyhow::Result;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::fs::File;
use std::io::{BufReader, IoSlice, Read};
use std::mem;
use std::os::unix::io::AsRawFd;

// Init logger
pub fn init_logger() {
    if env::var("RUST_LOG").is_ok() {
        simple_logger::init_with_env().unwrap();
    } else {
        simple_logger::init_with_level(log::Level::Info).unwrap();
    }
}

/*
struct FileAsPath(File);
impl AsRef<Path> for FileAsPath {
    fn as_ref(&self) -> &Path {
        self.0
    }
}
*/

/// This function computes the SHA-256 digest of a file
pub fn sha256_digest(input: &File) -> Result<String> {
    //let file = File::open(input).context("Failed to open input file")?;

    let mut reader = BufReader::new(input);

    let digest = {
        let mut hasher = Sha256::new();
        let mut buffer = [0; 1048576];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        hasher.finalize()
    };
    Ok(format!("{:x}", digest))
}

/// This function returns a bool weither
/// a file is hidden or not.
/// This is a filter on regular files ans not hidden ones.
/// We do not want to catch .bashrc like files.
///
/// Example:
/// ```
/// let walker = WalkDir::new("foo").into_iter();
/// for entry in walker.filter_entry(|e| !is_not_hidden(e)) {
///    let entry = entry.unwrap();
///    println!("{}", entry.path().display());
/// ```
/*
fn is_not_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| entry.depth() == 0 || !s.starts_with('.'))
        .unwrap_or(false)
}
*/

/// This function lists all files in a directory except hidden ones.
///
/// Example:
/// ```
/// let dir = tempdir().unwrap();
/// let path = dir.path().join("transit");
/// let _output = fs::create_dir_all(&path).unwrap();
/// assert_eq!(true, Path::new(&path).exists());
/// let file = path.join("file.txt");
/// let _output = File::create(&file).unwrap();
/// assert_eq!(true, Path::new(&file).exists());
/// let files = list_files(path.to_str().unwrap());
/// assert_eq!(files.unwrap(), ["file.txt"]);
/// ```
pub fn list_files(directory: &str) -> Result<Vec<String>> {
    let paths: std::fs::ReadDir = fs::read_dir(directory)?;

    let mut names = paths
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str().map(String::from))
            })
        })
        .collect::<Vec<String>>();
    // Not sending any files starting with dot like .bashrc
    let re = Regex::new(r"^\.([a-z])*")?;
    names.retain(|x| !re.is_match(x));
    Ok(names)
}

pub fn convert_ioslice<'a>(
    files: &'a Vec<File>,
    input: &'a Vec<Vec<u8>>,
) -> (Vec<IoSlice<'a>>, Vec<i32>) {
    let mut ios: Vec<IoSlice> = Vec::new();
    let mut fds: Vec<i32> = Vec::new();
    for i in input {
        ios.push(IoSlice::new(&i[..]));
    }

    for file in files {
        fds.push(file.as_raw_fd());
        mem::forget(file);
    }
    (ios, fds)
}
