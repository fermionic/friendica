<h1>$title</h1>
<form  enctype="multipart/form-data" action="$baseurl/index.php?q=uimport" method="post">
	<input type="hidden" name="pass" value="2">
	<input type="hidden" name="uid" value="$uid">
	<input type="hidden" name="dbname" value="$dbname">
	<label for="file">Database file:</label>
	<input type="file" name="dbUpload" value="$upload" id="file" /> 
</form>

