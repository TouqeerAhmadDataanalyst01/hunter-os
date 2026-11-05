<?php function q(){ $id = $_GET['id']; global $wpdb; $wpdb->query("SELECT * FROM users WHERE id=$id"); }
