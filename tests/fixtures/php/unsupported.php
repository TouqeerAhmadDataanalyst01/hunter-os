<?php
function visit_items($items) {
    foreach ($items as $item) {
        process_item($item);
    }
}
