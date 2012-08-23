<?php

function uexport_init(&$a) {

	if(! local_user())
		killme();

	$r = q("SELECT * FROM `user` WHERE `uid` = %d LIMIT 1",
		local_user()
	);
	if(! count($r))
		killme();

	$filename = "/" . $r['nickname'] . ".sqlite";
	$db = new PDO("sqlite:" . $filename . ";");
	$db->exec("CREATE TABLE IF NOT EXISTS user (
		uid integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		guid text NOT NULL,
		username text NOT NULL,
		password text NOT NULL,
		nickname text NOT NULL,
		email text NOT NULL,
		openid text NOT NULL,
		timezone text NOT NULL,
		language text NOT NULL DEFAULT 'en',
		register_date text NOT NULL DEFAULT '0000-00-00 00:00:00',
		login_date text NOT NULL DEFAULT '0000-00-00 00:00:00',
		default-location text NOT NULL,
		allow_location integer NOT NULL DEFAULT '0',
		theme text NOT NULL,
		pubkey text NOT NULL,
		prvkey text NOT NULL,
		spubkey text NOT NULL,
		sprvkey text NOT NULL,
		verified integer NOT NULL DEFAULT '0',
		blocked integer NOT NULL DEFAULT '0',
		blockwall integer NOT NULL DEFAULT '0',
		hidewall integer NOT NULL DEFAULT '0',
		blocktags integer NOT NULL DEFAULT '0',
		unkmail integer NOT NULL DEFAULT '0',
		cntunkmail integer NOT NULL DEFAULT '10',
		notify-flags integer NOT NULL DEFAULT '65535',
		page-flags integer NOT NULL DEFAULT '0',
		prvnets integer NOT NULL DEFAULT '0',
		pwdreset text NOT NULL,
		maxreq integer NOT NULL DEFAULT '10',
		expire integer NOT NULL DEFAULT '0',
		account_removed integer NOT NULL DEFAULT '0',
		account_expired integer NOT NULL DEFAULT '0',
		account_expires_on text NOT NULL DEFAULT '0000-00-00 00:00:00',
		expire_notification_sent text NOT NULL DEFAULT '0000-00-00 00:00:00',
		service_class text NOT NULL,
		def_gid integer NOT NULL DEFAULT '0',
		allow_cid text NOT NULL,
		allow_gid text NOT NULL,
		deny_cid text NOT NULL,
		deny_gid text NOT NULL,
		openidserver text NOT NULL
	);");
	$db->exec("CREATE TABLE IF NOT EXISTS contact (
		id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		uid integer NOT NULL,
		created text NOT NULL DEFAULT '0000-00-00 00:00:00',
		self integer NOT NULL DEFAULT '0',
		remote_self integer NOT NULL DEFAULT '0',
		rel integer NOT NULL DEFAULT '0',
		duplex integer NOT NULL DEFAULT '0',
		network text NOT NULL,
		name text NOT NULL,
		nick text NOT NULL,
		attag text NOT NULL,
		photo text NOT NULL,
		thumb text NOT NULL,
		micro text NOT NULL,
		site-pubkey text NOT NULL,
		issued-id text NOT NULL,
		dfrn-id text NOT NULL,
		url text NOT NULL,
		nurl text NOT NULL,
		addr text NOT NULL,
		alias text NOT NULL,
		pubkey text NOT NULL,
		prvkey text NOT NULL,
		batch text NOT NULL,
		request text NOT NULL,
		notify text NOT NULL,
		poll text NOT NULL,
		confirm text NOT NULL,
		poco text NOT NULL,
		aes_allow integer NOT NULL DEFAULT '0',
		ret-aes integer NOT NULL DEFAULT '0',
		usehub integer NOT NULL DEFAULT '0',
		subhub integer NOT NULL DEFAULT '0',
		hub-verify text NOT NULL,
		last-update text NOT NULL DEFAULT '0000-00-00 00:00:00',
		success_update text NOT NULL DEFAULT '0000-00-00 00:00:00',
		name-date text NOT NULL DEFAULT '0000-00-00 00:00:00',
		uri-date text NOT NULL DEFAULT '0000-00-00 00:00:00',
		avatar-date text NOT NULL DEFAULT '0000-00-00 00:00:00',
		term-date text NOT NULL DEFAULT '0000-00-00 00:00:00',
		priority integer NOT NULL,
		blocked integer NOT NULL DEFAULT '1',
		readonly integer NOT NULL DEFAULT '0',
		writable integer NOT NULL DEFAULT '0',
		forum integer NOT NULL DEFAULT '0',
		prv integer NOT NULL DEFAULT '0',
		hidden integer NOT NULL DEFAULT '0',
		archive integer NOT NULL DEFAULT '0',
		pending integer NOT NULL DEFAULT '1',
		rating integer NOT NULL DEFAULT '0',
		reason text NOT NULL,
		closeness integer NOT NULL DEFAULT '99',
		info text NOT NULL,
		profile-id integer NOT NULL DEFAULT '0',
		bdyear text NOT NULL,
		bd date NOT NULL
	);");
	$db->exec("CREATE TABLE IF NOT EXISTS group (
	  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	  uid integer NOT NULL,
	  visible integer NOT NULL DEFAULT '0',
	  deleted integer NOT NULL DEFAULT '0',
	  name text NOT NULL
	);");
	$db->exec("CREATE TABLE IF NOT EXISTS group_member (
	  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	  uid integer NOT NULL,
	  gid integer NOT NULL,
	  contact-id integer NOT NULL
	);");
	$db->exec("CREATE TABLE IF NOT EXISTS profile (
		id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		uid integer NOT NULL,
		profile-name text NOT NULL,
		is-default integer NOT NULL DEFAULT '0',
		hide-friends integer NOT NULL DEFAULT '0',
		name text NOT NULL,
		pdesc text NOT NULL,
		dob text NOT NULL DEFAULT '0000-00-00',
		address text NOT NULL,
		locality text NOT NULL,
		region text NOT NULL,
		postal-code text NOT NULL,
		country-name text NOT NULL,
		hometown text NOT NULL,
		gender text NOT NULL,
		marital text NOT NULL,
		with text NOT NULL,
		howlong text NOT NULL default '0000-00-00 00:00:00',
		sexual text NOT NULL,
		politic text NOT NULL,
		religion text NOT NULL,
		pub_keywords text NOT NULL,
		prv_keywords text NOT NULL,
		likes text NOT NULL,
		dislikes text NOT NULL,
		about text NOT NULL,
		summary text NOT NULL,
		music text NOT NULL,
		book text NOT NULL,
		tv text NOT NULL,
		film text NOT NULL,
		interest text NOT NULL,
		romance text NOT NULL,
		work text NOT NULL,
		education text NOT NULL,
		contact text NOT NULL,
		homepage text NOT NULL,
		photo text NOT NULL,
		thumb text NOT NULL,
		publish integer NOT NULL DEFAULT '0',
		net-publish integer NOT NULL DEFAULT '0'
	);");
	$db->exec("CREATE TABLE IF NOT EXISTS attach (
	  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	  uid integer NOT NULL,
	  hash text NOT NULL,
	  filename text NOT NULL,
	  filetype text NOT NULL,
	  filesize integer NOT NULL,
	  data blob NOT NULL,
	  created text NOT NULL DEFAULT '0000-00-00 00:00:00',
	  edited text NOT NULL DEFAULT '0000-00-00 00:00:00',
	  allow_cid text NOT NULL,
	  allow_gid text NOT NULL,
	  deny_cid text NOT NULL,
	  deny_gid text NOT NULL
	);");
	$db->exec("CREATE TABLE IF NOT EXISTS event (
	  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	  uid integer NOT NULL,
	  cid integer NOT NULL,
	  uri text NOT NULL,
	  created text NOT NULL,
	  edited text NOT NULL,
	  start text NOT NULL,
	  finish text NOT NULL,
	  summary text NOT NULL,
	  desc text NOT NULL,
	  location text NOT NULL,
	  type text NOT NULL,
	  nofinish integer NOT NULL DEFAULT '0',
	  adjust integer NOT NULL DEFAULT '1',
	  allow_cid text NOT NULL,
	  allow_gid text NOT NULL,
	  deny_cid text NOT NULL,
	  deny_gid text NOT NULL
	);");
	$db->exec("CREATE TABLE IF NOT EXISTS conv (
		id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		guid text NOT NULL,
		recips text NOT NULL,
		uid integer NOT NULL,
		creator text NOT NULL,
		created text NOT NULL DEFAULT '0000-00-00 00:00:00',
		updated text NOT NULL DEFAULT '0000-00-00 00:00:00',
		subject text NOT NULL
	);");
	$db->exec("CREATE TABLE IF NOT EXISTS mail (
	  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	  uid integer NOT NULL,
	  guid text NOT NULL,
	  from-name text NOT NULL,
	  from-photo text NOT NULL,
	  from-url text NOT NULL,
	  contact-id text NOT NULL,
	  convid integer NOT NULL,
	  title text NOT NULL,
	  body text NOT NULL,
	  seen integer NOT NULL,
	  reply integer NOT NULL DEFAULT '0',
	  replied integer NOT NULL,
	  unknown integer NOT NULL DEFAULT '0',
	  uri text NOT NULL,
	  parent-uri text NOT NULL,
	  created text NOT NULL DEFAULT '0000-00-00 00:00:00',
	);");
	$db->exec("CREATE TABLE IF NOT EXISTS mailacct (
	  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	  uid integer NOT NULL,
	  server text NOT NULL,
	  port integer NOT NULL,
	  ssltype text NOT NULL,
	  mailbox text NOT NULL,
	  user text NOT NULL,
	  pass text NOT NULL,
	  action integer NOT NULL,
	  movetofolder text NOT NULL,
	  reply_to text NOT NULL,
	  pubmail integer NOT NULL DEFAULT '0',
	  last_check text NOT NULL DEFAULT '0000-00-00 00:00:00',
	);");
	$db->exec("CREATE TABLE IF NOT EXISTS photo (
	  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	  uid integer NOT NULL,
	  contact-id integer NOT NULL DEFAULT '0',
	  guid text NOT NULL,
	  resource-id text NOT NULL,
	  created text NOT NULL,
	  edited text NOT NULL,
	  title text NOT NULL,
	  desc text NOT NULL,
	  album text NOT NULL,
	  filename text NOT NULL,
	  type CHAR(128);
	  height integer NOT NULL,
	  width integer NOT NULL,
	  data blob NOT NULL,
	  scale integer NOT NULL,
	  profile integer NOT NULL DEFAULT '0',
	  allow_cid text NOT NULL,
	  allow_gid text NOT NULL,
	  deny_cid text NOT NULL,
	  deny_gid text NOT NULL,
	);");
	$db->exec("CREATE TABLE IF NOT EXISTS search (
	  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	  uid integer NOT NULL,
	  term text NOT NULL,
	);");
	$db->exec("CREATE TABLE IF NOT EXISTS item (
		id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		guid text NOT NULL,
		uri text CHARACTER SET ascii NOT NULL,
		uid integer NOT NULL DEFAULT '0',
		contact-id integer NOT NULL DEFAULT '0',
		type text NOT NULL,
		wall integer NOT NULL DEFAULT '0',
		gravity integer NOT NULL DEFAULT '0',
		parent integer NOT NULL DEFAULT '0',
		parent-uri text CHARACTER SET ascii NOT NULL,
		extid text NOT NULL,
		thr-parent text NOT NULL,
		created text NOT NULL,
		edited text NOT NULL,
		commented text NOT NULL DEFAULT '0000-00-00 00:00:00',
		received text NOT NULL DEFAULT '0000-00-00 00:00:00',
		changed text NOT NULL DEFAULT '0000-00-00 00:00:00',
		owner-name text NOT NULL,
		owner-link text NOT NULL,
		owner-avatar text NOT NULL,
		author-name text NOT NULL,
		author-link text NOT NULL,
		author-avatar text NOT NULL,
		title text NOT NULL,
		body text NOT NULL,
		app text NOT NULL,
		verb text NOT NULL,
		object-type text NOT NULL,
		object text NOT NULL,
		target-type text NOT NULL,
		target text NOT NULL,
		postopts text NOT NULL,
		plink text NOT NULL,
		resource-id text NOT NULL,
		event-id integer NOT NULL,
		tag text NOT NULL,
		attach text NOT NULL,
		inform text NOT NULL,
		file text NOT NULL,
		location text NOT NULL,
		coord text NOT NULL,
		allow_cid text NOT NULL,
		allow_gid text NOT NULL,
		deny_cid text NOT NULL,
		deny_gid text NOT NULL,
		private integer NOT NULL DEFAULT '0',
		pubmail integer NOT NULL DEFAULT '0',
		moderated integer NOT NULL DEFAULT '0',
		visible integer NOT NULL DEFAULT '0',
		spam integer NOT NULL DEFAULT '0',
		starred integer NOT NULL DEFAULT '0',
		bookmark integer NOT NULL DEFAULT '0',
		unseen integer NOT NULL DEFAULT '1',
		deleted integer NOT NULL DEFAULT '0',
		origin integer NOT NULL DEFAULT '0',
		forum_mode integer NOT NULL DEFAULT '0',
		last-child integer NOT NULL DEFAULT '1'
	);");



	foreach($r as $line)
		$db->exec("INSERT INTO user (" . implode(",", array_keys($line)) . ") VALUES (" . implode(",", $line) . ");");

	$tables = array('contact', 'group', 'group_member', 'profile', 'attach', 'event', 'conv', 'mail', 'mailacct', 'photo', 'search');

	foreach($tables as $table) {

		$r = q("SELECT count(*) as total FROM " . $table . " WHERE `uid` = %d ",
			intval(local_user())
		);
		if(count($r))
			$total = $r[0]['total'];
		else
			$total = 0;

		for($x = 0; $x < $total; $x += 500) {
			$r = q("SELECT * FROM %s WHERE uid = %d LIMIT %d, %d",
				$table,
				intval(local_user()),
				intval($x),
				intval(500)
			);
			if(count($r)) {
				foreach($r as $line)
					$db->exec("INSERT INTO " . $table . " (" . implode(",", array_keys($line)) . ") VALUES (" . implode(",", $line) . ");");
			}
		}
	}


	$r = q("SELECT count(*) as `total` FROM `item` WHERE `uid` = %d ",
		intval(local_user())
	);
	if(count($r))
		$total = $r[0]['total'];
	else
		$total = 0;

	// chunk the items table to avoid exhausting memory

	for($x = 0; $x < $total; $x += 500) {
		$r = q("SELECT * FROM `item` WHERE `uid` = %d LIMIT %d, %d",
			intval(local_user()),
			intval($x),
			intval(500)
		);
		if(count($r)) {
			foreach($r as $item_line) {
				if($item_line['deleted'] !== 1)
					$db->exec("INSERT INTO item (" . implode(",", array_keys($item_line)) . ") VALUES (" . implode(",", $item_line) . ");");
			}
		}
	}

	$db = NULL;

	header('Content-Type: application/octet-stream');
	header('Content-Disposition: attachment; filename="'.basename($filename).'"');
	header('Content-Transfer-Encoding: binary');
	header('Content-Length: '.filesize($filename));
	header('Expires: 0');

#	$handle = fopen($filename, 'rb');
#	fpassthru($handle);
#	fclose($handle);
	ob_clean();
    flush();	
	readfile($filename);


/*	$user = array();
	$r = q("SELECT * FROM `user` WHERE `uid` = %d LIMIT 1",
		local_user()
	);
	if(count($r)) {
		foreach($r as $rr)
			foreach($rr as $k => $v)
				$user[$k] = $v;

	}
	$contact = array();
	$r = q("SELECT * FROM `contact` WHERE `uid` = %d ",
		intval(local_user())
	);
	if(count($r)) {
		foreach($r as $rr)
			foreach($rr as $k => $v)
				$contact[][$k] = $v;

	}

	$profile = array();
	$r = q("SELECT * FROM `profile` WHERE `uid` = %d ",
		intval(local_user())
	);
	if(count($r)) {
		foreach($r as $rr)
			foreach($rr as $k => $v)
				$profile[][$k] = $v;
	}

	$output = array('user' => $user, 'contact' => $contact, 'profile' => $profile );

	header("Content-type: application/json");
	echo json_encode($output);

	$r = q("SELECT count(*) as `total` FROM `item` WHERE `uid` = %d ",
		intval(local_user())
	);
	if(count($r))
		$total = $r[0]['total'];

	// chunk the output to avoid exhausting memory

	for($x = 0; $x < $total; $x += 500) {
		$item = array();
		$r = q("SELECT * FROM `item` WHERE `uid` = %d LIMIT %d, %d",
			intval(local_user()),
			intval($x),
			intval(500)
		);
		if(count($r)) {
			foreach($r as $rr)
				foreach($rr as $k => $v)
					$item[][$k] = $v;
		}

		$output = array('item' => $item);
		echo json_encode($output);
	}
*/

	killme();

}
