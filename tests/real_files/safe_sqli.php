<?php function q(){ global $wpdb; $id = $_GET['id']; $wpdb->query($wpdb->prepare("SELECT * FROM users WHERE id=%d", $id)); }
