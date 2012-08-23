<h1>$title</h1>

	<h2>$message_title</h2>
	{{ for $messages as $message }}
		$message <br />
	{{ endfor }}

{{ if $success == 2}}
	<h2>$success_title</h2>
	$success_message <br />

	{{ for $manual_contacts as $contact }}
	<a href="$contact.request">$contact.name</a> <br />
	{{ endfor }}
{{ elseif $success == 1 }}
	<h2>$contact_title</h2>
	$contact_message <br />
{{ else }}
	<h2>$startover_title</h2>
	$startover_message <br />
{{ endif }}

	<form action="$baseurl/index.php?q=uimport" method="post">
	{{ if $success != 0 }}
		<input type="hidden" name="uid" value="$uid">
		<input type="hidden" name="dbname" value="$dbname">
		<input type="hidden" name="pass" value="3">
		<input type="submit" value="$finish">
	{{ else }}
		<input type="hidden" name="pass" value="1">
		<input type="submit" value="$startover">
	{{ endif }}
	</form>

