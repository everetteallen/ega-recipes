<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Description</key>
	<string>Downloads Firefox disk image and builds a package, then uploads to the JSS.
Credit to the original creators of the firefox.jss recipe, Homebysix and Novaksam</string>
	<key>Identifier</key>
	<string>com.github.everetteallen.ega-recipes.jss-upload.Firefox</string>
	<key>Input</key>
	<dict>
		<key>CATEGORY</key>
		<string>Productivity</string>
		<key>NAME</key>
		<string>Firefox</string>
	</dict>
	<key>MinimumVersion</key>
	<string>0.4.0</string>
	<key>ParentRecipe</key>
	<string>com.github.autopkg.pkg.Firefox_EN</string>
	<key>Process</key>
	<array>
		<dict>
			<key>Arguments</key>
			<dict>
				<key>category</key>
				<string>%CATEGORY%</string>
				<key>prod_name</key>
				<string>%NAME%</string>
			</dict>
			<key>Processor</key>
			<string>JSSImporter</string>
		</dict>
	</array>
</dict>
</plist>