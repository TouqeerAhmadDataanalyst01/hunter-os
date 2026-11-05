<?php add_action('wp_ajax_nopriv_delete', 'del'); function del(){ $id = $_POST['id']; wp_delete_post($id); }
