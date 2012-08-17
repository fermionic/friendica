<?php

require_once('include/config.php');
require_once('include/network.php');
require_once('include/plugin.php');
require_once('include/text.php');
require_once('include/pgettext.php');
require_once('include/datetime.php');

function create_user($arr) {

	// Required: { username, nickname, email } or { openid_url }

	$a = get_app();
	$result = array('success' => false, 'user' => null, 'password' => '', 'message' => '');

	$using_invites = get_config('system','invitation_only');
	$num_invites   = get_config('system','number_invites');


	$invite_id  = ((x($arr,'invite_id'))  ? notags(trim($arr['invite_id']))  : '');
	$username   = ((x($arr,'username'))   ? notags(trim($arr['username']))   : '');
	$nickname   = ((x($arr,'nickname'))   ? notags(trim($arr['nickname']))   : '');
	$email      = ((x($arr,'email'))      ? notags(trim($arr['email']))      : '');
	$openid_url = ((x($arr,'openid_url')) ? notags(trim($arr['openid_url'])) : '');
	$photo      = ((x($arr,'photo'))      ? notags(trim($arr['photo']))      : '');
	$password   = ((x($arr,'password'))   ? trim($arr['password'])           : '');
	$blocked    = ((x($arr,'blocked'))    ? intval($arr['blocked'])  : 0);
	$verified   = ((x($arr,'verified'))   ? intval($arr['verified']) : 0);

	$publish    = ((x($arr,'profile_publish_reg') && intval($arr['profile_publish_reg'])) ? 1 : 0);
	$netpublish = ((strlen(get_config('system','directory_submit_url'))) ? $publish : 0);
		
	$tmp_str = $openid_url;

	if($using_invites) {
		if(! $invite_id) {
			$result['message'] .= t('An invitation is required.') . EOL;
			return $result;
		}
		$r = q("select * from register where `hash` = '%s' limit 1", dbesc($invite_id));
		if(! results($r)) {
			$result['message'] .= t('Invitation could not be verified.') . EOL;
			return $result;
		}
	} 

	if((! x($username)) || (! x($email)) || (! x($nickname))) {
		if($openid_url) {
			if(! validate_url($tmp_str)) {
				$result['message'] .= t('Invalid OpenID url') . EOL;
				return $result;
			}
			$_SESSION['register'] = 1;
			$_SESSION['openid'] = $openid_url;
			require_once('library/openid.php');
			$openid = new LightOpenID;
			$openid->identity = $openid_url;
			$openid->returnUrl = $a->get_baseurl() . '/openid'; 
			$openid->required = array('namePerson/friendly', 'contact/email', 'namePerson');
			$openid->optional = array('namePerson/first','media/image/aspect11','media/image/default');
			goaway($openid->authUrl());
			// NOTREACHED	
		}

		notice( t('Please enter the required information.') . EOL );
		return;
	}

	if(! validate_url($tmp_str))
		$openid_url = '';


	$err = '';

	// collapse multiple spaces in name
	$username = preg_replace('/ +/',' ',$username);

	if(mb_strlen($username) > 48)
		$result['message'] .= t('Please use a shorter name.') . EOL;
	if(mb_strlen($username) < 3)
		$result['message'] .= t('Name too short.') . EOL;

	// I don't really like having this rule, but it cuts down
	// on the number of auto-registrations by Russian spammers
	
	//  Using preg_match was completely unreliable, due to mixed UTF-8 regex support
	//	$no_utf = get_config('system','no_utf');
	//	$pat = (($no_utf) ? '/^[a-zA-Z]* [a-zA-Z]*$/' : '/^\p{L}* \p{L}*$/u' ); 

	// So now we are just looking for a space in the full name. 
	
	$loose_reg = get_config('system','no_regfullname');
	if(! $loose_reg) {
		$username = mb_convert_case($username,MB_CASE_TITLE,'UTF-8');
		if(! strpos($username,' '))
			$result['message'] .= t("That doesn't appear to be your full \x28First Last\x29 name.") . EOL;
	}


	if(! allowed_email($email))
		$result['message'] .= t('Your email domain is not among those allowed on this site.') . EOL;

	if((! valid_email($email)) || (! validate_email($email)))
		$result['message'] .= t('Not a valid email address.') . EOL;
		
	// Disallow somebody creating an account using openid that uses the admin email address,
	// since openid bypasses email verification. We'll allow it if there is not yet an admin account.

	if((x($a->config,'admin_email')) && (strcasecmp($email,$a->config['admin_email']) == 0) && strlen($openid_url)) {
		$r = q("SELECT * FROM `user` WHERE `email` = '%s' LIMIT 1",
			dbesc($email)
		);
		if(count($r))
			$result['message'] .= t('Cannot use that email.') . EOL;
	}

	$nickname = $arr['nickname'] = strtolower($nickname);

	if(! preg_match("/^[a-z][a-z0-9\-\_]*$/",$nickname))
		$result['message'] .= t('Your "nickname" can only contain "a-z", "0-9", "-", and "_", and must also begin with a letter.') . EOL;
	$r = q("SELECT `uid` FROM `user`
               	WHERE `nickname` = '%s' LIMIT 1",
               	dbesc($nickname)
	);
	if(count($r))
		$result['message'] .= t('Nickname is already registered. Please choose another.') . EOL;

	// Check deleted accounts that had this nickname. Doesn't matter to us,
	// but could be a security issue for federated platforms.

	$r = q("SELECT * FROM `userd`
               	WHERE `username` = '%s' LIMIT 1",
               	dbesc($nickname)
	);
	if(count($r))
		$result['message'] .= t('Nickname was once registered here and may not be re-used. Please choose another.') . EOL;

	if(strlen($result['message'])) {
		return $result;
	}

	$new_password = ((strlen($password)) ? $password : autoname(6) . mt_rand(100,9999));
	$new_password_encoded = hash('whirlpool',$new_password);

	$result['password'] = $new_password;

	require_once('include/crypto.php');

	$keys = new_keypair(4096);

	if($keys === false) {
		$result['message'] .= t('SERIOUS ERROR: Generation of security keys failed.') . EOL;
		return $result;
	}

	$default_service_class = get_config('system','default_service_class');
	if(! $default_service_class)
		$default_service_class = '';


	$prvkey = $keys['prvkey'];
	$pubkey = $keys['pubkey'];

	/**
	 *
	 * Create another keypair for signing/verifying
	 * salmon protocol messages. We have to use a slightly
	 * less robust key because this won't be using openssl
	 * but the phpseclib. Since it is PHP interpreted code
	 * it is not nearly as efficient, and the larger keys
	 * will take several minutes each to process.
	 *
	 */
	
	$sres    = new_keypair(512);
	$sprvkey = $sres['prvkey'];
	$spubkey = $sres['pubkey'];

	$r = q("INSERT INTO `user` ( `guid`, `username`, `password`, `email`, `openid`, `nickname`,
		`pubkey`, `prvkey`, `spubkey`, `sprvkey`, `register_date`, `verified`, `blocked`, `timezone`, `service_class` )
		VALUES ( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %d, 'UTC', '%s' )",
		dbesc(generate_user_guid()),
		dbesc($username),
		dbesc($new_password_encoded),
		dbesc($email),
		dbesc($openid_url),
		dbesc($nickname),
		dbesc($pubkey),
		dbesc($prvkey),
		dbesc($spubkey),
		dbesc($sprvkey),
		dbesc(datetime_convert()),
		intval($verified),
		intval($blocked),
		dbesc($default_service_class)
	);

	if($r) {
		$r = q("SELECT * FROM `user` 
			WHERE `username` = '%s' AND `password` = '%s' LIMIT 1",
			dbesc($username),
			dbesc($new_password_encoded)
		);
		if($r !== false && count($r)) {
			$u = $r[0];
			$newuid = intval($r[0]['uid']);
		}
	}
	else {
		$result['message'] .=  t('An error occurred during registration. Please try again.') . EOL ;
		return $result;
	} 		

	/**
	 * if somebody clicked submit twice very quickly, they could end up with two accounts 
	 * due to race condition. Remove this one.
	 */

	$r = q("SELECT `uid` FROM `user`
               	WHERE `nickname` = '%s' ",
               	dbesc($nickname)
	);
	if((count($r) > 1) && $newuid) {
		$result['message'] .= t('Nickname is already registered. Please choose another.') . EOL;
		q("DELETE FROM `user` WHERE `uid` = %d LIMIT 1",
			intval($newuid)
		);
		return $result;
	}

	if(x($newuid) !== false) {
		$r = q("INSERT INTO `profile` ( `uid`, `profile-name`, `is-default`, `name`, `photo`, `thumb`, `publish`, `net-publish` )
			VALUES ( %d, '%s', %d, '%s', '%s', '%s', %d, %d ) ",
			intval($newuid),
			t('default'),
			1,
			dbesc($username),
			dbesc($a->get_baseurl() . "/photo/profile/{$newuid}.jpg"),
			dbesc($a->get_baseurl() . "/photo/avatar/{$newuid}.jpg"),
			intval($publish),
			intval($netpublish)

		);
		if($r === false) {
			$result['message'] .=  t('An error occurred creating your default profile. Please try again.') . EOL;
			// Start fresh next time.
			$r = q("DELETE FROM `user` WHERE `uid` = %d",
				intval($newuid));
			return $result;
		}
		$r = q("INSERT INTO `contact` ( `uid`, `created`, `self`, `name`, `nick`, `photo`, `thumb`, `micro`, `blocked`, `pending`, `url`, `nurl`,
			`request`, `notify`, `poll`, `confirm`, `poco`, `name-date`, `uri-date`, `avatar-date`, `closeness` )
			VALUES ( %d, '%s', 1, '%s', '%s', '%s', '%s', '%s', 0, 0, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 0 ) ",
			intval($newuid),
			datetime_convert(),
			dbesc($username),
			dbesc($nickname),
			dbesc($a->get_baseurl() . "/photo/profile/{$newuid}.jpg"),
			dbesc($a->get_baseurl() . "/photo/avatar/{$newuid}.jpg"),
			dbesc($a->get_baseurl() . "/photo/micro/{$newuid}.jpg"),
			dbesc($a->get_baseurl() . "/profile/$nickname"),
			dbesc(normalise_link($a->get_baseurl() . "/profile/$nickname")),
			dbesc($a->get_baseurl() . "/dfrn_request/$nickname"),
			dbesc($a->get_baseurl() . "/dfrn_notify/$nickname"),
			dbesc($a->get_baseurl() . "/dfrn_poll/$nickname"),
			dbesc($a->get_baseurl() . "/dfrn_confirm/$nickname"),
			dbesc($a->get_baseurl() . "/poco/$nickname"),
			dbesc(datetime_convert()),
			dbesc(datetime_convert()),
			dbesc(datetime_convert())
		);

		// Create a group with no members. This allows somebody to use it 
		// right away as a default group for new contacts. 

		require_once('include/group.php');
		group_add($newuid, t('Friends'));

	}

	// if we have no OpenID photo try to look up an avatar
	if(! strlen($photo))
		$photo = avatar_img($email);

	// unless there is no avatar-plugin loaded
	if(strlen($photo)) {
		require_once('include/Photo.php');
		$photo_failure = false;

		$filename = basename($photo);
		$img_str = fetch_url($photo,true);
		// guess mimetype from headers or filename
		$type = guess_image_type($photo,true);

		
		$img = new Photo($img_str, $type);
		if($img->is_valid()) {

			$img->scaleImageSquare(175);

			$hash = photo_new_resource();

			$r = $img->store($newuid, 0, $hash, $filename, t('Profile Photos'), 4 );

			if($r === false)
				$photo_failure = true;

			$img->scaleImage(80);

			$r = $img->store($newuid, 0, $hash, $filename, t('Profile Photos'), 5 );

			if($r === false)
				$photo_failure = true;

			$img->scaleImage(48);

			$r = $img->store($newuid, 0, $hash, $filename, t('Profile Photos'), 6 );

			if($r === false)
				$photo_failure = true;

			if(! $photo_failure) {
				q("UPDATE `photo` SET `profile` = 1 WHERE `resource-id` = '%s' ",
					dbesc($hash)
				);
			}
		}
	}

	call_hooks('register_account', $newuid);

	$result['success'] = true;
	$result['user'] = $u;
	return $result;

}


function import_user($user, $self_contact, $profiles) {

	// Required: { username, nickname, email } or { openid_url }

	$a = get_app();
	$result = array('success' => false, 'user' => null, 'message' => '');

/*	$using_invites = get_config('system','invitation_only');
	$num_invites   = get_config('system','number_invites');


	$invite_id  = ((x($user,'invite_id'))  ? notags(trim($user['invite_id']))  : '');*/
	//$username   = $user['username']; //((x($user,'username'))   ? notags(trim($user['username']))   : '');
	//$nickname   = $user['nickname']; //((x($user,'nickname'))   ? notags(trim($user['nickname']))   : '');
	//$email      = $user['email']; //((x($user,'email'))      ? notags(trim($user['email']))      : '');
	//$openid_url = $user['openid']; //((x($user,'openid')) ? notags(trim($user['openid_url'])) : '');
//	$photo      = ((x($user,'photo'))      ? notags(trim($user['photo']))      : '');
//	$password   = $user['password']; //((x($user,'password'))   ? trim($user['password'])           : '');
//	$blocked    = 0; //((x($user,'blocked'))    ? intval($user['blocked'])  : 0);
//	$verified   = 0; //((x($user,'verified'))   ? intval($user['verified']) : 0);
//	$timezone   = $user['timezone'];

//	$prvkey = $user['prvkey'];
//	$pubkey = $user['pubkey'];
//	$sprvkey = $user['sprvkey'];
//	$spubkey = $user['spubkey'];


//	$publish    = ((x($user,'profile_publish_reg') && intval($user['profile_publish_reg'])) ? 1 : 0);

	$tmp_str = $user['openid'];

/*	if($using_invites) {
		if(! $invite_id) {
			$result['message'] .= t('An invitation is required.') . EOL;
			return $result;
		}
		$r = q("select * from register where `hash` = '%s' limit 1", dbesc($invite_id));
		if(! results($r)) {
			$result['message'] .= t('Invitation could not be verified.') . EOL;
			return $result;
		}
	} */

	// START CHECKING FOR ERRORS
	// XXX NEED A BETTER WAY TO INTERACT IF ERROR IS FOUND

	if((! x($user['username'])) || (! x($user['email'])) || (! x($user['nickname']))) {
		if($user['openid']) {
			if(! validate_url($tmp_str)) {
				$result['message'] .= t('Invalid OpenID url') . EOL;
				return $result;
			}
/*			$_SESSION['register'] = 1;
			$_SESSION['openid'] = $openid_url;
			require_once('library/openid.php');
			$openid = new LightOpenID;
			$openid->identity = $openid_url;
			$openid->returnUrl = $a->get_baseurl() . '/openid'; 
			$openid->required = array('namePerson/friendly', 'contact/email', 'namePerson');
			$openid->optional = array('namePerson/first','media/image/aspect11','media/image/default');
			goaway($openid->authUrl());*/
			// NOTREACHED	
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
		return $result;
	}

	// END CHECKING FOR ERRORS

	$default_service_class = get_config('system','default_service_class');
	if(! $default_service_class)
		$default_service_class = '';

	// XXX WHERE DOES 'publish' COME FROM?
	$netpublish = ((strlen(get_config('system','directory_submit_url'))) ? $publish : 0);
		
	unset($user['uid']);
	unset($user['login_date']);
	unset($user['theme']);

	$user['guid'] = generate_user_guid();
	$user['verified'] = 0;
	$user['blocked'] = 0;
	$user['register_date'] = datetime_convert();
	$user['service_class'] = $default_service_class;

	$r = q("INSERT INTO `user` ( guid, username, password, nickname, email, openid,
		timezone, language, register_date, `default-location`, allow_location,
		pubkey, prvkey, spubkey, sprvkey, verified, blocked, blockwall, hidewall,
		blocktags, unkmail, cntunkmail, `notify-flags`, `page-flags`, prvnets, pwdreset,
		maxreq, expire, account_removed, account_expired, account_expires_on,
		expire_notification_sent, service_class, def_gid, allow_cid, allow_gid,
		deny_cid, deny_gid, openidserver )
		VALUES ( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
		'%s', '%s', '%s', '%s', %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, '%s', %d,
		%d, %d, %d, '%s', '%s', '%s', %d, '%s', '%s', '%s', '%s', '%s' )",
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
		intval($user['def_gid']),
		dbesc($user['allow_cid']),
		dbesc($user['allow_gid']),
		dbesc($user['deny_cid']),
		dbesc($user['deny_gid']),
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
		return $result;
	}

	if(x($newuid) !== false) {
		foreach($profiles as $profile) {
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
				intval($profile['net-publish'])
			);
			if($r === false) {
				$result['message'] .=  t('An error occurred importing your profile "' . $profile['profile-name'] . '". Please try again.') . EOL;
				// Start fresh next time.
				$r = q("DELETE FROM `user` WHERE `uid` = %d",
					intval($newuid));
				$r = q("DELETE FROM profile WHERE uid = %d",
					intval($newuid));
				return $result;
			}
		}

// XXX CHECK `site-pubkey`,
		$r = q("INSERT INTO `contact` ( uid, created, self, name, nick, attag, photo, thumb, micro,
			`issued-id`, `dfrn-id`, url, nurl, alias, pubkey, prvkey, batch, request, notify, poll,
			confirm, poco, aes_allow, `ret-aes`, usehub, subhub, `hub-verify`, `name-date`, `uri-date`,
			`avatar-date`, `term-date`, priority, blocked, readonly, writable, forum, prv, hidden,
			archive, pending, rating, reason, closeness, info, `profile-id`, bdyear, bd )
			VALUES ( %d, '%s', 1, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
			'%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %d, %d, %d, %s, %s, %s, %s, %s, %d, 0, %d,
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
			dbesc($self_contact['batch']), // XXX CHECK
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

		// Create a group with no members. This allows somebody to use it 
		// right away as a default group for new contacts. 

	// XXX IMPORT GROUPS
/*		require_once('include/group.php');
		group_add($newuid, t('Friends'));*/

	}


	// XXX IMPORT PROFILE PHOTO
	// if we have no OpenID photo try to look up an avatar
	if(! strlen($photo))
		$photo = avatar_img($user['email']);

	// unless there is no avatar-plugin loaded
	if(strlen($photo)) {
		require_once('include/Photo.php');
		$photo_failure = false;

		$filename = basename($photo);
		$img_str = fetch_url($photo,true);
		// guess mimetype from headers or filename
		$type = guess_image_type($photo,true);

		
		$img = new Photo($img_str, $type);
		if($img->is_valid()) {

			$img->scaleImageSquare(175);

			$hash = photo_new_resource();

			$r = $img->store($newuid, 0, $hash, $filename, t('Profile Photos'), 4 );

			if($r === false)
				$photo_failure = true;

			$img->scaleImage(80);

			$r = $img->store($newuid, 0, $hash, $filename, t('Profile Photos'), 5 );

			if($r === false)
				$photo_failure = true;

			$img->scaleImage(48);

			$r = $img->store($newuid, 0, $hash, $filename, t('Profile Photos'), 6 );

			if($r === false)
				$photo_failure = true;

			if(! $photo_failure) {
				q("UPDATE `photo` SET `profile` = 1 WHERE `resource-id` = '%s' ",
					dbesc($hash)
				);
			}
		}
	}

	call_hooks('register_account', $newuid);

	$result['success'] = true;
	$result['user'] = $u;
	return $result;

}
