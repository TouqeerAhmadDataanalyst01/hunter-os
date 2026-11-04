<?php
function fetch_user($id) {
    $row = $wpdb->get_row($id);
    if ($id > 0) {
        return sanitize_text_field($row);
    } else {
        return null;
    }
}

class UserHandler {
    public function handle($request) {
        $name = $request->get_param('name');
        return fetch_user($name);
    }
}
