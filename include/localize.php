<?php

require_once('include/permissions.php');


if(! function_exists('item_extract_images')) {
function item_extract_images($body) {

	$saved_image = array();
	$orig_body = $body;
	$new_body = '';

	$cnt = 0;
	$img_start = strpos($orig_body, '[img');
	$img_st_close = ($img_start !== false ? strpos(substr($orig_body, $img_start), ']') : false);
	$img_end = ($img_start !== false ? strpos(substr($orig_body, $img_start), '[/img]') : false);
	while(($img_st_close !== false) && ($img_end !== false)) {

		$img_st_close++; // make it point to AFTER the closing bracket
		$img_end += $img_start;

		if(! strcmp(substr($orig_body, $img_start + $img_st_close, 5), 'data:')) {
			// This is an embedded image

			$saved_image[$cnt] = substr($orig_body, $img_start + $img_st_close, $img_end - ($img_start + $img_st_close));
			$new_body = $new_body . substr($orig_body, 0, $img_start) . '[!#saved_image' . $cnt . '#!]';

			$cnt++;
		}
		else
			$new_body = $new_body . substr($orig_body, 0, $img_end + strlen('[/img]'));

		$orig_body = substr($orig_body, $img_end + strlen('[/img]'));

		if($orig_body === false) // in case the body ends on a closing image tag
			$orig_body = '';

		$img_start = strpos($orig_body, '[img');
		$img_st_close = ($img_start !== false ? strpos(substr($orig_body, $img_start), ']') : false);
		$img_end = ($img_start !== false ? strpos(substr($orig_body, $img_start), '[/img]') : false);
	}

	$new_body = $new_body . $orig_body;

	return array('body' => $new_body, 'images' => $saved_image);
}}

if(! function_exists('item_redir_and_replace_images')) {
function item_redir_and_replace_images($body, $images, $cid) {

	$origbody = $body;
	$newbody = '';

	for($i = 0; $i < count($images); $i++) {
		$search = '/\[url\=(.*?)\]\[!#saved_image' . $i . '#!\]\[\/url\]' . '/is';
		$replace = '[url=' . z_path() . '/redir/' . $cid 
		           . '?f=1&url=' . '$1' . '][!#saved_image' . $i . '#!][/url]' ;

		$img_end = strpos($origbody, '[!#saved_image' . $i . '#!][/url]') + strlen('[!#saved_image' . $i . '#!][/url]');
		$process_part = substr($origbody, 0, $img_end);
		$origbody = substr($origbody, $img_end);

		$process_part = preg_replace($search, $replace, $process_part);
		$newbody = $newbody . $process_part;
	}
	$newbody = $newbody . $origbody;

	$cnt = 0;
	foreach($images as $image) {
		// We're depending on the property of 'foreach' (specified on the PHP website) that
		// it loops over the array starting from the first element and going sequentially
		// to the last element
		$newbody = str_replace('[!#saved_image' . $cnt . '#!]', '[img]' . $image . '[/img]', $newbody);
		$cnt++;
	}

	return $newbody;
}}

if(! function_exists('redir_private_attach')) {
function redir_private_attach($attachments) {

	logger('redir_private_attach', LOGGER_DEBUG);

	$a = get_app();
	$site = substr($a->get_baseurl(),strpos($a->get_baseurl(),'://'));

	$attach_arr = explode(',',$attachments);
	if(count($attach_arr)) {
		foreach($attach_arr as $attach) {
			$matches = false;
			$cnt = preg_match('|\[attach\]href=\"(.*?)\" length=\"(.*?)\" type=\"(.*?)\" title=\"(.*?)\"\[\/attach\]|',$attach,$matches);
			if($cnt) {
				$attach_url = $matches[1];

				if(stristr($attach_url , $site . '/attach/')) {
					// Only redirect to locally hosted attachments
					$replace = false;
					$attach_id = basename($attach_url);

					$r = q("SELECT id, uid, allow_cid, allow_gid, deny_cid, deny_gid FROM attach WHERE id = %d LIMIT 1",
						intval($attach_id)
					);
					if(count($r)) {

						// Check to see if we should replace this attachment link with a redirection
						// 1. No need to do so if the attachment is public
						// 2. See if the contact id of the item is in the access list
						//    for the attachment. If so, mark for redirection

						if(has_permissions($r[0])) {
							$recips = enumerate_permissions($r[0]);
							if(in_array($item['contact-id'], $recips)) {
								$replace = true;	
							}
						}
						if($replace) {
							logger('redir_private_attach: replacing attachment', LOGGER_DEBUG);
							$redir_url = z_path() . '/redir/' . $item['contact-id'] . '?f=1&url=' . $attach_url;
							$attach = str_replace('[attach]href="' . $attach_url . '"', '[attach]href="' . $redir_url . '"', $attach);
							logger('redir_private_attach: replaced: ' . $redir_url, LOGGER_DATA);
						}
					}
					else
						logger('redir_private_attach: attachment not found', LOGGER_DEBUG);
				}
			}
		}

		return implode(',', $attach_arr);
	}

	return $attachments;
}}

