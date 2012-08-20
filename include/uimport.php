<?php

require_once('include/config.php');
require_once('include/network.php');
require_once('include/plugin.php');
require_once('include/text.php');
require_once('include/pgettext.php');
require_once('include/datetime.php');
require_once('include/follow.php');


function import_user($dbname) {

	$a = get_app();
	$result = array('success' => false, 'user' => null, 'message' => '');


	$db = new PDO("sqlite:" . $dbname . ";");

	/***************************************
	 *          IMPORT USER TABLE          *
	 ***************************************/
	$r = $db->query("SELECT * FROM user LIMIT 1;");
	if(! $r) {
		$result['message'] .= t('No user information found') . EOL;

		$db = NULL;
		return $result;
	}
	$user = $r[0];

	// START CHECKING FOR ERRORS
	// XXX NEED A BETTER WAY TO INTERACT IF ERROR IS FOUND

	$tmp_str = $user['openid'];
	if((! x($user['username'])) || (! x($user['email'])) || (! x($user['nickname']))) {
		if($user['openid']) {
			if(! validate_url($tmp_str)) {
				$result['message'] .= t('Invalid OpenID url') . EOL;

				$db = NULL;
				return $result;
			}
		}
		else {

			$result['message'] .= t('User import must have a username, an email, and a nickname.') . EOL;
			return $result;
		}
	}

	if(! validate_url($tmp_str))
		$user['openid'] = '';


	$err = '';

	// collapse multiple spaces in name
	$user['username'] = preg_replace('/ +/',' ',$user['username']);

	if(mb_strlen($user['username']) > 48)
		$result['message'] .= t('Username is too long.') . EOL;
	if(mb_strlen($user['username']) < 3)
		$result['message'] .= t('Username is too short.') . EOL;

	// I don't really like having this rule, but it cuts down
	// on the number of auto-registrations by Russian spammers
	
	//  Using preg_match was completely unreliable, due to mixed UTF-8 regex support
	//	$no_utf = get_config('system','no_utf');
	//	$pat = (($no_utf) ? '/^[a-zA-Z]* [a-zA-Z]*$/' : '/^\p{L}* \p{L}*$/u' ); 

	// So now we are just looking for a space in the full name. 
	
	$loose_reg = get_config('system','no_regfullname');
	if(! $loose_reg) {
		$user['username'] = mb_convert_case($user['username'],MB_CASE_TITLE,'UTF-8');
		if(! strpos($user['username'],' '))
			$result['message'] .= t("That doesn't appear to be your full \x28First Last\x29 name.") . EOL;
	}


	if(! allowed_email($user['email']))
		$result['message'] .= t('Your email domain is not among those allowed on this site.') . EOL;

	if((! valid_email($user['email'])) || (! validate_email($user['email'])))
		$result['message'] .= t('Not a valid email address.') . EOL;
		
	// Disallow somebody creating an account using openid that uses the admin email address,
	// since openid bypasses email verification. We'll allow it if there is not yet an admin account.

	if((x($a->config,'admin_email')) && (strcasecmp($user['email'],$a->config['admin_email']) == 0) && strlen($user['openid'])) {
		$r = q("SELECT * FROM `user` WHERE `email` = '%s' LIMIT 1",
			dbesc($user['email'])
		);
		if(count($r))
			$result['message'] .= t('Cannot use that email.') . EOL;
	}

	$user['nickname'] = strtolower($user['nickname']);

	if(! preg_match("/^[a-z][a-z0-9\-\_]*$/",$user['nickname']))
		$result['message'] .= t('Your "nickname" can only contain "a-z", "0-9", "-", and "_", and must also begin with a letter.') . EOL;

	$r = q("SELECT `uid` FROM `user`
               	WHERE `nickname` = '%s' LIMIT 1",
               	dbesc($user['nickname'])
	);
	if(count($r))
		$result['message'] .= t('Nickname is already registered. Please choose another.') . EOL;

	// Check deleted accounts that had this nickname. Doesn't matter to us,
	// but could be a security issue for federated platforms.

	$r = q("SELECT * FROM `userd`
               	WHERE `username` = '%s' LIMIT 1",
               	dbesc($user['nickname'])
	);
	if(count($r))
		$result['message'] .= t('Nickname was once registered here and may not be re-used. Please choose another.') . EOL;

	if(strlen($result['message'])) {
		$db = NULL;
		return $result;
	}

	// END CHECKING FOR ERRORS

	$default_service_class = get_config('system','default_service_class');
	if(! $default_service_class)
		$default_service_class = '';

	/* When importing, we don't necessarily want to keep all the old information.
	 * All of the following fields should be re-created by the new hub:
	 *
	 *	uid
	 *	login_date
	 *	theme
	 *	guid
	 *	verified
	 *	blocked
	 *	register_date
	 *	service_class
	 *
	 * The following can't be imported until after contact invitations are sent
	 * out and groups are imported so that we know the ids that will be used for
	 * the contacts and groups:
	 *
	 *	def_gid
	 *	allow_cid
	 *	allow_gid
	 *	deny_cid
	 *	deny_gid
	 */

	$r = q("INSERT INTO `user` ( guid, username, password, nickname, email, openid,
		timezone, language, register_date, `default-location`, allow_location,
		pubkey, prvkey, spubkey, sprvkey, verified, blocked, blockwall, hidewall,
		blocktags, unkmail, cntunkmail, `notify-flags`, `page-flags`, prvnets, pwdreset,
		maxreq, expire, account_removed, account_expired, account_expires_on,
		expire_notification_sent, service_class, openidserver )
		VALUES ( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
		'%s', '%s', '%s', '%s', %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, '%s', %d,
		%d, %d, %d, '%s', '%s', '%s', '%s' )",
		dbesc(generate_user_guid()),
		dbesc($user['username']),
		dbesc($user['password']),
		dbesc($user['nickname']),
		dbesc($user['email']),
		dbesc($user['openid']),
		dbesc($user['timezone']),
		dbesc($user['language']),
		dbesc(datetime_convert()),
		dbesc($user['default-location']),
		dbesc($user['allow_location']),
		dbesc($user['pubkey']),
		dbesc($user['prvkey']),
		dbesc($user['spubkey']),
		dbesc($user['sprvkey']),
		intval($user['verified']),
		intval($user['blocked']),
		intval($user['blockwall']),
		intval($user['hidewall']),
		intval($user['blocktags']),
		intval($user['unkmail']),
		intval($user['cntunkmail']),
		intval($user['notify-flags']),
		intval($user['page-flags']),
		intval($user['prvnets']),
		dbesc($user['pwdreset']),
		intval($user['maxreq']),
		intval($user['expire']),
		intval($user['account_removed']),
		intval($user['account_expired']),
		dbesc($user['account_expires_on']),
		dbesc($user['expire_notification_sent']),
		dbesc($default_service_class)
		dbesc($user['openidserver'])
	);

	if($r) {
		$r = q("SELECT * FROM `user` 
			WHERE `username` = '%s' AND `password` = '%s' LIMIT 1",
			dbesc($user['username']),
			dbesc($user['password'])
		);
		if($r !== false && count($r)) {
			$u = $r[0];
			$newuid = intval($r[0]['uid']);
		}
	}
	else {
		$result['message'] .=  t('An error occurred during user import. Please try again.') . EOL ;

		$db = NULL;
		return $result;
	} 		

	/**
	 * if somebody clicked submit twice very quickly, they could end up with two accounts 
	 * due to race condition. Remove this one.
	 */

	$r = q("SELECT `uid` FROM `user`
               	WHERE `nickname` = '%s' ",
               	dbesc($user['nickname'])
	);
	if((count($r) > 1) && $newuid) {
		$result['message'] .= t('Please be patient and only submit once.') . EOL;
		q("DELETE FROM `user` WHERE `uid` = %d LIMIT 1",
			intval($newuid)
		);

		$db = NULL;
		return $result;
	}


	if(x($newuid) !== false) {
		/***************************************
		 *         IMPORT PROFILE TABLE        *
		 ***************************************/
		$profiles = $db->query("SELECT * FROM profile;");
		foreach($profiles as $profile) {
			$netpublish = ((strlen(get_config('system','directory_submit_url'))) ? $profile['publish'] : 0);

			$r = q("INSERT INTO profile ( uid, `profile-name`, `is-default`, `hide-friends`, name,
				pdesc, dob, address, locality, region, `postal-code`, `country-name`, hometown, gender,
				marital, with, howlong, sexual, politic, religion, pub_keywords, prv_keywords, likes,
				dislikes, about, summary, music, book, tv, film, interest, romance, work, education,
				contact, homepage, photo, thumb, publish, `net-publish` )
				VALUES ( %d, '%s', %d, %d, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
				'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
				'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %d ) ",
				intval($newuid),
				dbesc($profile['profile-name']),
				intval($profile['is-default']),
				intval($profile['hide-friends']),
				dbesc($profile['name']),
				dbesc($profile['pdesc']),
				dbesc($profile['dob']),
				dbesc($profile['address']),
				dbesc($profile['locality']),
				dbesc($profile['region']),
				dbesc($profile['postal-code']),
				dbesc($profile['country-name']),
				dbesc($profile['hometown']),
				dbesc($profile['gender']),
				dbesc($profile['marital']),
				dbesc($profile['with']),
				dbesc($profile['howlong']),
				dbesc($profile['sexual']),
				dbesc($profile['politic']),
				dbesc($profile['religion']),
				dbesc($profile['pub_keywords']),
				dbesc($profile['prv_keywords']),
				dbesc($profile['likes']),
				dbesc($profile['dislikes']),
				dbesc($profile['about']),
				dbesc($profile['summary']),
				dbesc($profile['music']),
				dbesc($profile['book']),
				dbesc($profile['tv']),
				dbesc($profile['film']),
				dbesc($profile['interest']),
				dbesc($profile['romance']),
				dbesc($profile['work']),
				dbesc($profile['education']),
				dbesc($profile['contact']),
				dbesc($profile['homepage']),
				dbesc($a->get_baseurl() . "/photo/profile/{$newuid}.jpg"),
				dbesc($a->get_baseurl() . "/photo/avatar/{$newuid}.jpg"),
				intval($profile['publish']),
				intval($netpublish)
			);
			if($r === false) {
				$result['message'] .=  t('An error occurred importing your profile "' . $profile['profile-name'] . '". Please try again.') . EOL;
				// Start fresh next time.
				$r = q("DELETE FROM `user` WHERE `uid` = %d",
					intval($newuid));
				$r = q("DELETE FROM profile WHERE uid = %d",
					intval($newuid));

				$db = NULL;
				return $result;
			}

			// make $profile_map using NOT IN (,,,,) query
		}
		// Should probably create a default profile if none are found



		/***************************************
		 *        IMPORT SELF CONTACT          *
		 ***************************************/
		$r = $db->query("SELECT * FROM CONTACT WHERE self = 1 LIMIT 1;");
		if(! $r) {
			$result['message'] .= t("Couldn't find self contact information") . EOL;
			// Start fresh next time.
			// It'd be better to just create a default self-contact
			$r = q("DELETE FROM `user` WHERE `uid` = %d",
				intval($newuid));
			$r = q("DELETE FROM profile WHERE uid = %d",
				intval($newuid));

			$db = NULL;
			return $result;
		}

		$self_contact = $r[0];

		/* The following fields are not kept:
		 *
		 *	site-pubkey	(only relevant for non-self contacts)
		 *	batch		(only relevant for Diaspora)
		 */
		$r = q("INSERT INTO `contact` ( uid, created, self, name, nick, attag, photo, thumb, micro,
			`issued-id`, `dfrn-id`, url, nurl, alias, pubkey, prvkey, request, notify, poll,
			confirm, poco, aes_allow, `ret-aes`, usehub, subhub, `hub-verify`, `name-date`, `uri-date`,
			`avatar-date`, `term-date`, priority, blocked, readonly, writable, forum, prv, hidden,
			archive, pending, rating, reason, closeness, info, `profile-id`, bdyear, bd )
			VALUES ( %d, '%s', 1, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
			'%s', '%s', '%s', '%s', '%s', '%s', %d, %d, %d, %d, %s, %s, %s, %s, %s, %d, 0, %d,
			%d, %d, %d, %d, %d, 0, %d, %s, %d, %s, %d, %s, %s ) ",
			intval($newuid),
			dbesc(datetime_convert()),
			dbesc($user['username']),
			dbesc($user['nickname']),
			dbesc($self_contact['attag']),
			dbesc($a->get_baseurl() . "/photo/profile/{$newuid}.jpg"),
			dbesc($a->get_baseurl() . "/photo/avatar/{$newuid}.jpg"),
			dbesc($a->get_baseurl() . "/photo/micro/{$newuid}.jpg"),
			dbesc($self_contact['issued-id']),
			dbesc($self_contact['dfrn-id']),
			dbesc($a->get_baseurl() . "/profile/$user['nickname']"),
			dbesc(normalise_link($a->get_baseurl() . "/profile/$user['nickname']")),
			dbesc($self_contact['alias']),
			dbesc($self_contact['pubkey']),
			dbesc($self_contact['prvkey']),
			dbesc($a->get_baseurl() . "/dfrn_request/$user['nickname']"),
			dbesc($a->get_baseurl() . "/dfrn_notify/$user['nickname']"),
			dbesc($a->get_baseurl() . "/dfrn_poll/$user['nickname']"),
			dbesc($a->get_baseurl() . "/dfrn_confirm/$user['nickname']"),
			dbesc($a->get_baseurl() . "/poco/$user['nickname']"),
			intval($self_contact['aes_allow']),
			intval($self_contact['ret-aes']),
			intval($self_contact['usehub']),
			intval($self_contact['subhub']),
			dbesc($self_contact['hub-verify']),
			dbesc($self_contact['name-date']),
			dbesc($self_contact['uri-date']),
			dbesc($self_contact['avatar-date']),
			dbesc($self_contact['term-date']),
			intval($self_contact['priority']),
			intval($self_contact['readonly']),
			intval($self_contact['writable']),
			intval($self_contact['forum']),
			intval($self_contact['prv']),
			intval($self_contact['hidden']),
			intval($self_contact['archive']),
			intval($self_contact['rating']),
			dbesc($self_contact['reason']),
			intval($self_contact['closeness'])
			dbesc($self_contact['info']),
			intval($self_contact['profile-id'])
			dbesc($self_contact['bdyear']),
			dbesc($self_contact['bd']),
		);
	}


	/***************************************
	 *        IMPORT PROFILE PHOTO         *
	 ***************************************/
	$r = $db->query("SELECT * FROM photo WHERE scale = 4 AND uid = " .  . " AND profile = 1 LIMIT 1;");

	if($r) {
		require_once('include/Photo.php');
		$profile_photo = $r[0];
		$photo_failure = false;

		
		$img = new Photo($profile_photo['data'], $profile_photo['type']);
		if($img->is_valid()) {

			$img->scaleImageSquare(175);

			$hash = $profile_photo['resource-id']; //photo_new_resource();

			$r = $img->store($newuid, 0, $hash, $profile_photo['filename'], t('Profile Photos'), 4 );

			if($r === false)
				$photo_failure = true;

			$img->scaleImage(80);

			$r = $img->store($newuid, 0, $hash, $profile_photo['filename'], t('Profile Photos'), 5 );

			if($r === false)
				$photo_failure = true;

			$img->scaleImage(48);

			$r = $img->store($newuid, 0, $hash, $profile_photo['filename'], t('Profile Photos'), 6 );

			if($r === false)
				$photo_failure = true;

			if(! $photo_failure) {
				q("UPDATE `photo` SET `profile` = 1 WHERE `resource-id` = '%s' ",
					dbesc($hash)
				);
			}
		}
	}
	// Need to set a default if no profile photo is found


	$db = NULL;

	call_hooks('register_account', $newuid);

	$result['success'] = true;
	$result['user'] = $u;
	return $result;

}


/***************************************
 *           IMPORT CONTACTS           *
 ***************************************/

function import_contacts($dbname, $uid, $profile_map) {

//	$a = get_app();
	$result = array('success' => false, 'message' => '', 'contact_map' => array(), 'manual_contacts' => array(), 'manual_text' => '');


	$db = new PDO("sqlite:" . $dbname . ";");

	$r = $db->query("SELECT * FROM contact WHERE self = 0 AND network != '" . NETWORK_DFRN . "';");
	if(! $r) {
		$result['message'] .= t('Unable to import contacts') . EOL;

		$db = NULL;
		return $result;
	}

	foreach($r as $contact) {

		switch(contact['network']) {
			case NETWORK_MAIL:
			case NETWORK_MAIL2:
				$url = 'mailto:' . contact['addr'];
				break;
			case NETWORK_DIASPORA:
				$url = contact['addr'];
				break;
			default:
				$url = contact['url'];
				break;
		}
		$url_ID = contact['url'];

		$result = new_contact($uid, $url);
		if(! $result['success']) {
			// deal with contact adding failure
			continue;
		}

		$r = q("SELECT id FROM contact WHERE uid = %d url = '%s'",
			intval($uid),
			dbesc($contact['url'])
		);
		if(! $r)
			continue;

		$newcontact = $r[0];
		$contact_map[$contact['id']] = $newcontact['id'];

		$r = q("UPDATE contact SET blocked, readonly, hidden, archive, info, `profile-id`
		        VALUES (%d, %d, %d, %d, %s, %d) WHERE id = %d",
		        intval($contact['blocked']),
		        intval($contact['readonly']),
		        intval($contact['hidden']),
		        intval($contact['archive']),
				dbesc($contact['info']),
		        intval($profile_map[$contact['profile-id']]),
				intval($newcontact['id'])
		);
	}

	$r = $db->query("SELECT id, name, nick, request, network, addr, url, blocked, readonly, hidden, archive,
	                 info, `profile-id` FROM contact WHERE self = 0 AND network = '" . NETWORK_DFRN . "';");
	if($r) {

		$manual_contacts = $r;
		$result['manual_text'] = "The following contacts could not be added automatically. Please follow the links to add each contact:" . EOL;
		foreach($manual_contacts as $dfrn_contact) {
			$name = ($dfrn_contact['name'] === '' ? $dfrn_contact['nick'] : $dfrn_contact['name']);
			$result['manual_text'] .= '<a href="' . $dfrn_contact['request'] . '">' . $name . '</a>' . EOL;
		}

		$result['manual_contacts'] = $manual_contacts;
	}

	$db = NULL;

	$result['contact_map'] = $contact_map;
	$result['success'] = true;
	return $result;
}


// finish_import_contacts does the wrap-up for contacts that
// had to be imported manually

function finish_import_contacts($dbname, $uid, $profile_map, $contact_map, $manual_contacts) {

	$result = array('success' => false, 'message' => '', 'contact_map' => $contact_map);


	$db = new PDO("sqlite:" . $dbname . ";");

	foreach($manual_contacts as $contact) {
		$r = q("SELECT id FROM contact WHERE uid = %d url = '%s'",
			intval($uid),
			dbesc($contact['url'])
		);
		if(! $r)
			continue;

		$newcontact = $r[0];
		$contact_map[$contact['id']] = $newcontact['id'];

		$r = q("UPDATE contact SET blocked, readonly, hidden, archive, info, `profile-id`
		        VALUES (%d, %d, %d, %d, %s, %d) WHERE id = %d",
		        intval($contact['blocked']),
		        intval($contact['readonly']),
		        intval($contact['hidden']),
		        intval($contact['archive']),
				dbesc($contact['info']),
		        intval($profile_map[$contact['profile-id']]),
				intval($newcontact['id'])
		);		
	}

	$db = NULL;

	$result['contact_map'] = $contact_map;
	$result['success'] = true;
	return $result;
}

function import_data($dbname, $uid, $contact_map) {

	$result = array('success' => false, 'message' => '');


	$db = new PDO("sqlite:" . $dbname . ";");


	/***************************************
	 *             IMPORT GROUPS           *
	 ***************************************/
	$r = $db->query("SELECT * FROM group;");
	if(! $r) {
		$result['message'] .= "Couldn't get group information from imported database" . EOL;
	}
	else {
		foreach($r as $group) {
			// The better way to do this is with a standard function, e.g. group_add.
			// However, group_add doesn't support adding not visible or deleted groups
			// at the moment, so for this proof of concept just add directly into the DB

			$r = q("INSERT INTO group ( uid, visible, deleted, name )
				    VALUES ( %d, %d, %d, '%s' )",
				    intval($uid),
				    intval($group['visible']),
				    intval($group['deleted']),
				    dbesc($group['name'])
			);

			$r = q("SELECT id FROM group WHERE uid = %d AND name = '%s'",
			        intval($uid),
					dbesc($group['name'])
			);
			if(! $r) {
				$result['message'] .= 'Problem adding group ' . $group['name'] . EOL;
				continue;
			}

			$group_map[$group['id']] = $r[0]['id'];
		}
	}


	/***************************************
	 *         IMPORT GROUP MEMBERS        *
	 ***************************************/

	$r = $db->query("SELECT * FROM group_member;");
	if(! $r) {
		$result['message'] .= "Couldn't get group member information from imported database" . EOL;
	}
	elseif($group_map && $contact_map) {
		foreach($r as $member) {
			$r = q("INSERT INTO group_member ( uid, gid, `contact-id` )
			        VALUES ( %d, %d, %d )",
			        intval($uid),
					intval($group_map[$member['gid']]),
					intval($contact_map[$member['contact-id']])
			);
		}
	}


	/***************************************
	 *          IMPORT ATTACHMENTS         *
	 ***************************************/

	// Transform old contact-ids and group-ids into the new ones using
	// SQL operations. This is more efficient and it enables us to avoid
	// possible memory issues with importing everything at once
	$old_cids = array_keys($contact_map);
	foreach($old_cids as $old_cid) {
		$r = $db->exec("UPDATE attach SET allow_cid, deny_cid
			            VALUES (REPLACE(allow_cid, '<" . $old_cid . ">', '<" . $contact_map[$old_cid] . ">'),
			                    REPLACE(deny_cid, '<" . $old_cid . ">', '<" . $contact_map[$old_cid] . ">'));");
	}

	// What should we do if group_map is empty? It's possible that the user has no
	// groups, in which case there's no problem. But what if we failed to import the
	// groups?
	$old_gids = array_keys($group_map);
	foreach($old_gids as $old_gid) {
		$r = $db->exec("UPDATE attach SET allow_gid, deny_gid
			            VALUES (REPLACE(allow_gid, '<" . $old_gid . ">', '<" . $group_map[$old_gid] . ">'),
			                    REPLACE(deny_gid, '<" . $old_gid . ">', '<" . $group_map[$old_gid] . ">'));");
	}

	// Attachments can be large, so let's only import one at a time from the DB
	$r = $db->query("SELECT id FROM attach;");
	if($r) {
		foreach($r as $aid) {
			$attach = $db->query("SELECT * FROM attach WHERE id = " . intval($aid) . " LIMIT 1;");
			if(! $attach)
				continue;

			$r = q("INSERT INTO attach ( uid, hash, filename, filetype, filesize, data, created, edited,
			        allow_cid, allow_gid, deny_cid, deny_gid )
			        VALUES ( %d, '%s', '%s', '%s', %d, '%s', '%s', '%s', '%s', '%s', '%s', '%s' )",
			        intval($uid),
					dbesc($attach[0]['hash']),
					dbesc($attach[0]['filename']),
					dbesc($attach[0]['filetype']),
			        intval($attach[0]['filesize']),
					dbesc($attach[0]['data']),
					dbesc($attach[0]['created']),
					dbesc($attach[0]['edited']),
					dbesc($attach[0]['allow_cid']),
					dbesc($attach[0]['allow_gid']),
					dbesc($attach[0]['deny_cid']),
					dbesc($attach[0]['deny_gid'])
			);

			$r = q("SELECT id FROM attach WHERE hash = '%s' LIMIT 1",
			        dbesc($attach[0]['hash'])
			);
			if($r) {
				$attach_map[$attach[0]['id']] = $r[0]['id'];
			}
			else {
				$result['message'] .= "Problem importing attachment " . $attach[0]['filename'] . EOL;
			}
		}
	}


	/***************************************
	 *            IMPORT PHOTOS            *
	 ***************************************/

	foreach($old_cids as $old_cid) {
		$r = $db->exec("UPDATE photo SET allow_cid, deny_cid
			            VALUES (REPLACE(allow_cid, '<" . $old_cid . ">', '<" . $contact_map[$old_cid] . ">'),
			                    REPLACE(deny_cid, '<" . $old_cid . ">', '<" . $contact_map[$old_cid] . ">'));");
	}

	foreach($old_gids as $old_gid) {
		$r = $db->exec("UPDATE photo SET allow_gid, deny_gid
			            VALUES (REPLACE(allow_gid, '<" . $old_gid . ">', '<" . $group_map[$old_gid] . ">'),
			                    REPLACE(deny_gid, '<" . $old_gid . ">', '<" . $group_map[$old_gid] . ">'));");
	}

	// Photos can be large, so let's only import one at a time from the DB
	$r = $db->query("SELECT id FROM photo;");
	if($r) {
		foreach($r as $pid) {
			$photo = $db->query("SELECT * FROM photo WHERE id = " . intval($pid) . " LIMIT 1;");
			if(! $photo)
				continue;

			$r = q("INSERT INTO photo ( uid, `contact-id`, guid, `resource-id`, created, edited, title,
			        desc, album, filename, type, height, width, data, scale,
			        allow_cid, allow_gid, deny_cid, deny_gid )
			        VALUES ( %d, %d, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %d, '%s', %d, '%s', '%s', '%s', '%s')",
			        intval($uid),
			        intval($photo[0]['contact-id']),
					dbesc($photo[0]['guid']),
					dbesc($photo[0]['resource-id']),
					dbesc($photo[0]['created']),
					dbesc($photo[0]['edited']),
					dbesc($photo[0]['title']),
					dbesc($photo[0]['desc']),
					dbesc($photo[0]['album']),
					dbesc($photo[0]['filename']),
					dbesc($photo[0]['type']),
					intval($photo[0]['height']),
					intval($photo[0]['width']),
					dbesc($photo[0]['data']),
					intval($photo[0]['scale']),
					dbesc($photo[0]['allow_cid']),
					dbesc($photo[0]['allow_gid']),
					dbesc($photo[0]['deny_cid']),
					dbesc($photo[0]['deny_gid'])
			);

			$r = q("SELECT id FROM photo WHERE `resource-id` = '%s' LIMIT 1",
			        dbesc($photo[0]['resource-id'])
			);
			if($r) {
				$photo_map[$photo[0]['id']] = $r[0]['id'];
			}
			else {
				$result['message'] .= "Problem importing photo " . $photo[0]['filename'] . EOL;
			}
		}
	}


	/***************************************
	 *            IMPORT EVENTS            *
	 ***************************************/

	foreach($old_cids as $old_cid) {
		$r = $db->exec("UPDATE event SET allow_cid, deny_cid
			            VALUES (REPLACE(allow_cid, '<" . $old_cid . ">', '<" . $contact_map[$old_cid] . ">'),
			                    REPLACE(deny_cid, '<" . $old_cid . ">', '<" . $contact_map[$old_cid] . ">'));");
	}

	foreach($old_gids as $old_gid) {
		$r = $db->exec("UPDATE event SET allow_gid, deny_gid
			            VALUES (REPLACE(allow_gid, '<" . $old_gid . ">', '<" . $group_map[$old_gid] . ">'),
			                    REPLACE(deny_gid, '<" . $old_gid . ">', '<" . $group_map[$old_gid] . ">'));");
	}

	// Chunk the events table to avoid exhausting memory.
	// Probably not necessary, but it's good to cover your
	// bases

	$r = $db->query("SELECT count(*) as total FROM event");
	if(count($r))
		$total = $r[0]['total'];
	else
		$total = 0;

	// Keep the URI from the old hub. That way there's no chance
	// of the URI conflicting with any existing URIs on the
	// new hub

	for($x = 0; $x < $total; $x += 500) {
		$r = $db->query("SELECT * FROM event LIMIT " . intval($x) . ", 500;");
		if($r) {
			foreach($r as $event) {
				$r = q("INSERT INTO event ( uid, cid, uri, created, edited, start, finish, summary, desc,
				        location, type, nofinish, adjust, allow_cid, allow_gid, deny_cid, deny_gid )
				        VALUES ( %d, %d, '%s', '%s', '%s', '%s', '%s', '%s', '%s',
				        '%s', '%s', %d, %d, '%s', '%s', '%s', '%s')",
				        intval($uid),
				        intval($contact_map[$event['cid']]),
				        dbesc($event['uri']),
				        dbesc($event['created']),
				        dbesc($event['edited']),
				        dbesc($event['start']),
				        dbesc($event['finish']),
				        dbesc($event['summary']),
				        dbesc($event['desc']),
				        dbesc($event['location']),
				        dbesc($event['type']),
				        intval($event['nofinish']),
				        intval($event['adjust']),
				        dbesc($event['allow_cid']),
				        dbesc($event['allow_gid']),
				        dbesc($event['deny_cid']),
				        dbesc($event['deny_gid'])
				);
			}
		}
	}


	/***************************************
	 *             IMPORT MAIL             *
	 ***************************************/

	// XXX NEED TO DO SOMETHING WITH THE conv TABLE AND CREATE conv_map

	// Chunk the mail table to avoid exhausting memory.
	// Probably not necessary, but it's good to cover your
	// bases

	$r = $db->query("SELECT count(*) as total FROM mail");
	if(count($r))
		$total = $r[0]['total'];
	else
		$total = 0;

	// Keep the URI from the old hub. That way there's no chance
	// of the URI conflicting with any existing URIs on the
	// new hub

	for($x = 0; $x < $total; $x += 500) {
		$r = $db->query("SELECT * FROM mail LIMIT " . intval($x) . ", 500;");
		if($r) {
			foreach($r as $mail) {
				$r = q("INSERT INTO mail ( uid, guid, `from-name`, `from-photo`, `from-url`, `contact-id`,
				        convid, title, body, seen, reply, replied, unknown, uri, `parent-uri`, created )
				        VALUES ( %d, '%s', '%s', '%s', '%s', '%s', %d, '%s', '%s', %d,
				        %d, %d, %d, '%s', '%s', '%s' )",
				        intval($uid),
				        dbesc($mail['guid']),
				        dbesc($mail['from-name']),
				        dbesc($mail['from-photo']),
				        dbesc($mail['from-url']),
				        dbesc($contact_map[intval($mail['contact-id'])]), // XXX Why isn't this an integer in the DB?
						intval($conv_map[$mail['convid']]),
				        dbesc($mail['title']),
				        dbesc($mail['body']),
						intval($mail['seen']),
						intval($mail['reply']),
						intval($mail['replied']),
						intval($mail['unknown']),
				        dbesc($mail['uri']),
				        dbesc($mail['parent-uri']),
				        dbesc($mail['created'])
				);
			}
		}
	}
				        

	/***************************************
	 *         IMPORT MAIL ACCOUNTS        *
	 ***************************************/

	$r = $db->query("SELECT * FROM mailacct;");
	if($r) {
		foreach($r as $mailacct) {
			$r = q("INSERT INTO mailacct ( uid, server, port, ssltype, mailbox, user,
			        pass, action, movetofolder, reply_to, pubmail, last_check )
			        VALUES ( %d, '%s', %d, '%s', '%s', '%s', '%s', %d, '%s', '%s', %d, '%s' )",
			        intval($uid),
			        dbesc($mailacct['server']),
					intval($mailacct['port']),
			        dbesc($mailacct['ssltype']),
			        dbesc($mailacct['mailbox']),
			        dbesc($mailacct['user']),
			        dbesc($mailacct['pass']),
					intval($mailacct['action']),
			        dbesc($mailacct['movetofolder']),
			        dbesc($mailacct['reply_to']),
					intval($mailacct['pubmail']),
			        dbesc($mailacct['last_check'])
			);

		}
	}


	/***************************************
	 *           IMPORT SEARCHES           *
	 ***************************************/

	$r = $db->query("SELECT * FROM search;");
	if($r) {
		foreach($r as $search) {
			$r = q("INSERT INTO search ( uid, term ) VALUES ( %d, '%s' )",
			        intval($uid),
			        dbesc($search['term'])
			);
		}
	}


	/***************************************
	 *            IMPORT ITEMS             *
	 ***************************************/

	foreach($old_cids as $old_cid) {
		$r = $db->exec("UPDATE item SET allow_cid, deny_cid
			            VALUES (REPLACE(allow_cid, '<" . $old_cid . ">', '<" . $contact_map[$old_cid] . ">'),
			                    REPLACE(deny_cid, '<" . $old_cid . ">', '<" . $contact_map[$old_cid] . ">'));");
	}

	foreach($old_gids as $old_gid) {
		$r = $db->exec("UPDATE item SET allow_gid, deny_gid
			            VALUES (REPLACE(allow_gid, '<" . $old_gid . ">', '<" . $group_map[$old_gid] . ">'),
			                    REPLACE(deny_gid, '<" . $old_gid . ">', '<" . $group_map[$old_gid] . ">'));");
	}

	// XXX The 'attach' field needs to be modified for the new location
	// XXX Image locations need to be fixed (in 'body', I think)
	// XXX Does anything else need to be fixed?

	// Chunk the item table to avoid exhausting memory.

	$r = $db->query("SELECT count(*) as total FROM item");
	if(count($r))
		$total = $r[0]['total'];
	else
		$total = 0;

	// Keep the URI from the old hub. That way there's no chance
	// of the URI conflicting with any existing URIs on the
	// new hub

	for($x = 0; $x < $total; $x += 500) {
		$r = $db->query("SELECT * FROM item LIMIT " . intval($x) . ", 500;");
		if($r) {
			foreach($r as $item) {
				$r = q("INSERT INTO item ( guid, uri, uid, `contact-id`, type, wall, gravity,
				        parent, `parent-uri`, extid, `thr-parent`, created, edited, commented,
				        received, changed, `owner-name`, `owner-link`, `owner-avatar`, `author-name`,
				        `author-link`, `author-avatar`, title, body, app, verb, `object-type`, object,
				        `target-type`, target, postops, plink, `resource-id`, `event-id`, tag, attach,
				        inform, file, location, coord, allow_cid, allow_gid, deny_cid, deny_gid,
				        private, pubmail, moderated, visible, spam, starred, bookmark, unseen, deleted,
				        origin, forum_mode, `last-child` )
				        VALUES ( '%s', '%s', %d, %d, '%s', %d, %d, %d, '%s', '%s', '%s', '%s', '%s', '%s',
				        '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
				        '%s', '%s', '%s', '%s', '%s', %d,  '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
				        '%s', '%s', %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d )",
				        dbesc($item['guid']),
				        dbesc($item['uri']),
				        intval($uid),
				        intval($contact_map[$item['contact-id']]),
				        dbesc($item['text']),
				        intval($item['wall']),
				        intval($item['gravity']),
				        intval($item['parent']),
				        dbesc($item['parent-uri']),
				        dbesc($item['extid']),
				        dbesc($item['thr-parent']),
				        dbesc($item['created']),
				        dbesc($item['edited']),
				        dbesc($item['commented']),
				        dbesc($item['received']),
				        dbesc($item['changed']),
				        dbesc($item['owner-name']),
				        dbesc($item['owner-link']), // XXX Does this need to be changed?
				        dbesc($item['owner-avatar']), // XXX Does this need to be changed?
				        dbesc($item['author-name']),
				        dbesc($item['author-link']), // XXX Does this need to be changed?
				        dbesc($item['author-avatar']), // XXX Does this need to be changed?
				        dbesc($item['title']),
				        dbesc($item['body']),
				        dbesc($item['app']),
				        dbesc($item['verb']),
				        dbesc($item['object-type']),
				        dbesc($item['object']),
				        dbesc($item['target-type']),
				        dbesc($item['target']),
				        dbesc($item['postops']),
				        dbesc($item['plink']), // XXX Does this need to be changed?
				        dbesc($item['resource-id']), // XXX DOES THIS NEED TO BE MAPPED?
				        dbesc($item['event-id']), // XXX DOES THIS NEED TO BE MAPPED?
				        dbesc($item['tag']), // XXX Does this need to be changed?
				        dbesc($item['attach']), // XXX Does this need to be changed?
				        dbesc($item['inform']),
				        dbesc($item['file']),
				        dbesc($item['location']),
				        dbesc($item['coord']),
				        dbesc($item['allow_cid']),
				        dbesc($item['allow_gid']),
				        dbesc($item['deny_cid']),
				        dbesc($item['deny_gid']),
				        intval($item['private']),
				        intval($item['pubmail']),
				        intval($item['moderated']),
				        intval($item['visible']),
				        intval($item['spam']),
				        intval($item['starred']),
				        intval($item['bookmark']),
				        intval($item['unseen']),
				        intval($item['deleted']),
				        intval($item['origin']),
				        intval($item['forum_mode']),
				        intval($item['last-child'])
				);
			}
		}
	}




	$db = NULL;

	$result['success'] = true;
	return $result;
}
