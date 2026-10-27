<?php
/*
Plugin Name: My Test Plugin
*/
// Test Case 1 - should be flagged as file upload
if (isset($_FILES['file'])) {
  move_uploaded_file($_FILES['file']['tmp_name'], '/tmp/uploaded');
}

// Test Case 2 - should be flagged as SQLi
global $wpdb;
$wpdb->query("SELECT * FROM users WHERE id = " . $_POST['id']);