#[cfg(test)]
mod tests {
    use crate::is_corrupted;
    use tempfile::tempdir;
    use std::fs::File;

    #[test]
    fn test_is_corrupted() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("file.txt");
        File::create(&file).unwrap();
        assert_eq!(false, is_corrupted(file));
        let file = dir.path().join("file.txt");
        let file_corrupted = dir.path().join("file.txt.ioerror");
        File::create(&file).unwrap();
        File::create(&file_corrupted).unwrap();
        assert_eq!(true, is_corrupted(file));
    }
}
