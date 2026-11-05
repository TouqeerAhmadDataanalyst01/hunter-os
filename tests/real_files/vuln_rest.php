<?php register_rest_route('my/v1', '/del', ['methods'=>'POST', 'callback'=>'del', 'permission_callback'=>'__return_true']); function del($r){ $id = $r['id']; echo $id; }
