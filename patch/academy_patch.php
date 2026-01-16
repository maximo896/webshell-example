<?php
// Academy LMS 3.5.0 Security Patch
// Usage: Upload this file to wp-content/mu-plugins/academy-patch.php
add_action('init', function() {
    if(isset($_POST['academy_reset_submit']) && isset($_GET['user_id'])) {
        $user = get_userdata(absint($_GET['user_id']));
        if(!$user || is_wp_error(check_password_reset_key($_GET['reset_key']??'', $user->user_login))) {
            wp_die('Invalid reset link', 'Security Check', ['response'=>403]);
        }
    }
}, 1);
