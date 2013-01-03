<?php
/* ACL selector json backend */

require_once("include/acl_selectors.php");
require_once("include/contact_selectors.php");

function acl_init(&$a){
	acl_lookup($a);
}


