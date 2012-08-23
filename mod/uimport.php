<?php

require_once("include/uimport_functions.php");

$uimport_pass = 1;


function uimport_init(&$a){
	
	global $uimport_pass;

	if (x($_POST,'pass'))
		$uimport_pass = intval($_POST['pass']);

}

function uimport_post(&$a) {
	global $uimport_pass, $dbname, $uid, $messages, $manual_contacts, $success;

	switch($uimport_pass) {
		case 1:
			return;
			break;
		case 2: // Import user information and try to automatically import contacts
			// it'd be good to check if the file is a SQLite DB

			$success = 0;

			$target_path = "/";
			$dbname = $target_path . basename($_FILES['dbUpload']['name']); 

			if(move_uploaded_file($_FILES['dbUpload']['tmp_name'], $dbname)) {
				// success
			} else{
				// failure
			}

			$result = import_user($dbname);
			$messages = $result['message'];
			if(! $result['success'])
				return;

			$uid = $result['uid'];
			$profile_map = $result['profile_map'];

			$success = 1;

			$result = import_contacts($dbname, $uid, $profile_map);
			$messages = $messages + $result['message'];
			if(! $result['success'])
				return;

			$contact_map = $result['contact_map'];
			$manual_contacts = $result['manual_contacts'];

			$success = 2;

			// Store some things in the DB that we'll need on subsequent passes
			$db = new PDO("sqlite:" . $dbname . ";");

			$db->exec("CREATE TABLE profile_map (
			           old_id integer NOT NULL PRIMARY KEY,
			           new_id integer NOT NULL
			           );");
			foreach($profile_map as $old_id => $new_id) {
				$db->exec("INSERT INTO profile_map (old_id, new_id) VALUES (" . $old_id . "," . $new_id . ");");
			}

			$db->exec("CREATE TABLE contact_map (
			           old_id integer NOT NULL PRIMARY KEY,
			           new_id integer NOT NULL
			           );");
			foreach($contact_map as $old_id => $new_id) {
				$db->exec("INSERT INTO contact_map (old_id, new_id) VALUES (" . $old_id . "," . $new_id . ");");
			}

			$db->exec("CREATE TABLE manual_contacts (
			           id integer NOT NULL PRIMARY KEY
			           );");
			foreach($manual_contacts as $contact) {
				$db->exec("INSERT INTO manual_contacts (id) VALUES ('" . $contact['id'] . "');");
				$contact['name'] = ( trim($contact['name']) === '' ? $contact['nick'] : $contact['name'] );
			}

			$db = NULL;

			return;
			break;
		case 3:
			$db = new PDO("sqlite:" . $dbname . ";");

			$r = $db->query("SELECT * FROM profile_map");
			if(! $r)
				return;

			foreach($r as $line) {
				$profile_map[$line['old_id']] = $line['new_id'];
			}

			$r = $db->query("SELECT * FROM contact_map");
			if(! $r)
				return;

			foreach($r as $line) {
				$contact_map[$line['old_id']] = $line['new_id'];
			}

			$r = $db->query("SELECT * FROM manual_contacts");
			if(! $r)
				return;

			foreach($r as $line) {
				$manual_contacts[] = $line['id'];
			}

			$db = NULL;

			$result = finish_import_contacts($dbname, $uid, $profile_map, $contact_map, $manual_contacts);
			$messages = $result['message'];

			if(! $result['success'])
				return;

			$contact_map = $result['contact_map'];

			$result = import_data($dbname, $uid, $contact_map);

			$messages = $messages + $result['message'];

			return; 
			break;
	}
}

function uimport_content(&$a) {

	global $uimport_pass, $dbname, $uid, $messages, $manual_contacts, $success;
	$o = '';
	
	switch ($uimport_pass){
		case 1: { // Ask for user DB upload

			$tpl = get_markup_template('uimport_upload.tpl');
			$o .= replace_macros($tpl, array(
				'$title' => t('Import User Database'),
				'$baseurl' => $a->get_baseurl(),
				'$dbname' => $dbname,
				'$uid' => $uid,
				'$upload' => t('Upload'),

			));
			return $o;
		}; break;
		
		case 2: { // List contacts that need to be added manually

			$tpl = get_markup_template('uimport_contacts.tpl');
			$o .= replace_macros($tpl, array(
				'$title' => t('User Import Status'),
				'$messagetitle' => t('Messages'),
				'$success_title' => t('Manual Contact Import'),
				'$success_message' => t('The following contacts could not be added automatically. Please click each of the links to add them manually. When you are finished, click "Finish".'),
				'$contact_title' => t('Contact Import Problem'),
				'$contact_message' => t('Couldn\'t import your contacts. You will have to add them manually.'),
				'$startover_title' => t('User Import Problem'),
				'$startover_message' => t('There was a problem importing your user account from the database you uploaded. Please try again.'),
				'$messages' => $messages,
				'$manual_contacts' => $manual_contacts,
				'$baseurl' => $a->get_baseurl(),
				'$dbname' => $dbname,
				'$uid' => $uid,
				'$success' => $success,
				'$finish' => t('Finish'),
				'$startover' => t('Start over'),
				
			));
			return $o;
		}; break;
		case 3: { // Final status
			$tpl = get_markup_template('uimport_final.tpl');
			$o .= replace_macros($tpl, array(
				'$title' => t('User Import Complete'),
				'$messagetitle' => t('Messages'),
				
			));
			return $o;
		}; break;
			
	}
}


