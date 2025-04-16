    #[test]
    fn test_file_operations() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = b"Hello, file system!";
        
        temp_file.write_all(test_data).unwrap();
        temp_file.flush().unwrap();
        
        // Test reading the file
        let read_data = read_file(temp_file.path()).unwrap();
        assert_eq!(read_data, test_data);
        
        // Test computing hash
        let hash = hash_file_sha256(temp_file.path()).unwrap();
        assert_eq!(hash.len(), 32); // SHA-256 is 32 bytes
        
        // Test file exists
        assert!(file_exists(temp_file.path()));
        
        // Test writing to a new file
        let new_temp_file = NamedTempFile::new().unwrap();
        let new_path = new_temp_file.path().to_path_buf();
        let new_data = b"New file content";
        
        write_file(&new_path, new_data).unwrap();
        let read_new_data = read_file(&new_path).unwrap();
        assert_eq!(read_new_data, new_data);
    }
    
    #[test]
    fn test_json_serialization() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct TestStruct {
            name: String,
            value: i32,
            tags: Vec<String>,
        }
        
        let test_obj = TestStruct {
            name: "test".to_string(),
            value: 42,
            tags: vec!["tag1".to_string(), "tag2".to_string()],
        };
        
        // Serialize to JSON
        let json = to_json(&test_obj).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("42"));
        assert!(json.contains("tag1"));
        
        // Deserialize from JSON
        let deserialized: TestStruct = from_json(&json).unwrap();
        assert_eq!(deserialized, test_obj);
    }
    
    #[test]
    fn test_path_utilities() {
        // Test path joining
        let base = PathBuf::from("/tmp");
        let joined = join_paths(&base, "subdir");
        assert_eq!(joined, PathBuf::from("/tmp/subdir"));
        
        // Test with nested paths
        let joined2 = join_paths(&joined, "file.txt");
        assert_eq!(joined2, PathBuf::from("/tmp/subdir/file.txt"));
        
        // Test directory creation and existence
        let temp_dir = tempfile::tempdir().unwrap();
        let test_dir = temp_dir.path().join("test_dir");
        
        assert!(!dir_exists(&test_dir));
        ensure_dir_exists(&test_dir).unwrap();
        assert!(dir_exists(&test_dir));
        
        // Test nested directory creation
        let nested_dir = test_dir.join("nested/deep/path");
        ensure_dir_exists(&nested_dir).unwrap();
        assert!(dir_exists(&nested_dir));
    }
    
    #[test]
    fn test_random_string_generation() {
        // Test random string with specific length
        let random1 = random_string(10);
        let random2 = random_string(10);
        
        assert_eq!(random1.len(), 10);
        assert_eq!(random2.len(), 10);
        assert_ne!(random1, random2); // Should be different (very high probability)
        
        // Test ID generation
        let id1 = generate_id("test");
        let id2 = generate_id("test");
        
        assert!(id1.starts_with("test-"));
        assert!(id2.starts_with("test-"));
        assert_ne!(id1, id2);
        
        // IDs should contain timestamp
        let now = current_time_secs();
        let now_str = now.to_string();
        assert!(id1.contains(&now_str) || id1.contains(&(now-1).to_string()) || id1.contains(&(now+1).to_string()));
    }
    
    #[test]
    fn test_constant_time_comparison() {
        // Equal arrays
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        assert!(constant_time_eq(&a, &b));
        
        // Different arrays same length
        let c = [1, 2, 3, 4, 6];
        assert!(!constant_time_eq(&a, &c));
        
        // Different length arrays
        let d = [1, 2, 3, 4];
        assert!(!constant_time_eq(&a, &d));
        
        // Empty arrays
        let e: [u8; 0] = [];
        let f: [u8; 0] = [];
        assert!(constant_time_eq(&e, &f));
    }
    
    #[test]
    fn test_config_dir() {
        // Skip test if home directory can't be determined
        if let Some(home) = home_dir() {
            let config_dir = create_config_dir().unwrap();
            assert!(config_dir.starts_with(home));
            assert!(config_dir.ends_with(".trustchain"));
            assert!(dir_exists(&config_dir));
        }
    }
}
