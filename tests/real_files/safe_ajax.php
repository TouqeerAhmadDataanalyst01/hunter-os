<?php add_action('wp_ajax_delete', 'del'); function del(){ if(!current_user_can('delete_posts')) return; $id = $_POST['id']; wp_delete_post($id); }
