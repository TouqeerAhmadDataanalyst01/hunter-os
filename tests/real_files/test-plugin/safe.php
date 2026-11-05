<?php function safe(){ $id = sanitize_text_field($_GET['id']); echo esc_html($id); }
